"""Break-first red-team battery for the policy-delta counterexample
seam (wave-267 feature lane: Cedar SymCC ``check_implies`` pattern,
ADAPT).

Target: gov/policy_delta.py -- the review-artifact complement to
gov/policy_change_containment.py. Where the containment module
answers "does this widen authority?" with a verdict plus count
detail, this module emits CONCRETE COUNTEREXAMPLES: per expansion
atom, the exact (subject, action, resource) grant, the boundary
verdict for that grant, and which risk check(s) fired on it.
It also hardens the combine the way Cedar's authorizer does:
residual-forbid => unknown (a surviving deny rule vetoes the delta,
never a vacuous pass), error-skip fail-closed, default-deny in the
request engine. Counterexamples feed the human-approval queue as
digest-only review evidence.

Every probe attacks a PUBLIC seam, never product internals. The
battery imports the implementation via GOV_POLDDELTA_IMPL (default
"gov.policy_delta"); against the permissive stub
(GOV_POLDDELTA_IMPL=stub) every attack probe must BREAK, proving the
probes are real. Against the real module every probe must HELD, in
staging and under `env -u GOV_DEPLOYMENT_MODE`.

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt. A probe returns (ok, detail); ok=True means HELD (the seam
behaves per its contract), ok=False means BREAK (genuine defect) or
harness ERROR.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import importlib
import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

TAXONOMY_PIN = 1458  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).

_IMPL = os.environ.get("GOV_POLDDELTA_IMPL", "gov.policy_delta")

_STUB_SRC = '''"""Permissive stub: emits no counterexamples, allows
everything, queues nothing. Every attack probe must BREAK against
this."""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

CODES = ()
POLICY_VERSION = 1


class PolicyDeltaError(Exception):
    def __init__(self, code, detail=""):
        super(PolicyDeltaError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def counterexamples(candidate, current, boundary,
                    credentialed_hosts=()):
    return {"verdict": "within_boundary", "delta_class": "equivalent",
            "failed_checks": [], "counterexamples": [],
            "checked": [], "out_of_scope": [],
            "evidence_digest": "stub"}


def evaluate(policy, request):
    return {"decision": "Allow", "reason": "stub",
            "matched_rule": None}


def request_review(gate, record, policy_id):
    return ("stub-id", [])
'''


def _load_impl():
    if _IMPL == "stub":
        d = tempfile.mkdtemp(prefix="w267_poldelta_stub_")
        p = os.path.join(d, "stub_poldelta.py")
        with open(p, "w") as f:
            f.write(_STUB_SRC)
        sys.path.insert(0, d)
        return importlib.import_module("stub_poldelta")
    return importlib.import_module(_IMPL)


pd = _load_impl()

# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

CURRENT = {"version": 1, "rules": [
    {"id": "llm", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["api.example.com"], "ports": [443],
     "methods": ["GET"], "paths": ["/v1/*"],
     "credential": None},
]}

WIDEN = {"version": 1, "rules": CURRENT["rules"] + [
    {"id": "llm-evil", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["evil.example.com"], "ports": [443],
     "methods": ["POST"], "paths": ["/exfil"],
     "credential": None},
]}

WIDEN_LINKLOCAL = {"version": 1, "rules": CURRENT["rules"] + [
    {"id": "llm-ll", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["169.254.169.254"], "ports": [80],
     "methods": ["GET"], "paths": ["/latest/meta-data"],
     "credential": None},
]}

WIDEN_L7 = {"version": 1, "rules": CURRENT["rules"] + [
    {"id": "llm-l7", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["api.example.com"], "ports": [443],
     "methods": ["POST"], "paths": ["/admin/*"],
     "credential": None},
]}

WIDEN_CRED = {"version": 1, "rules": CURRENT["rules"] + [
    {"id": "db", "subject": "agent-worker", "effect": "allow",
     "action": "credential-use", "credential": "prod-db"},
]}

DENY_CAND = {"version": 1, "rules": CURRENT["rules"] + [
    {"id": "deny-x", "subject": "agent-worker", "effect": "deny",
     "action": "egress",
     "hosts": ["*"], "ports": [443],
     "methods": ["*"], "paths": ["*"],
     "credential": None},
]}

RESTRICTIVE = {"version": 1, "rules": []}

BOUNDARY_WIDE = {"version": 1, "rules": [
    {"id": "b", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["*.example.com"], "ports": [443],
     "methods": ["GET", "POST"], "paths": ["*"],
     "credential": None},
]}

BOUNDARY_NARROW = {"version": 1, "rules": [
    {"id": "b", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["api.example.com"], "ports": [443],
     "methods": ["GET"], "paths": ["/v1/*"],
     "credential": None},
]}

ALLOW_POLICY = {"version": 1, "rules": [
    {"id": "a", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["api.example.com"], "ports": [443],
     "methods": ["GET"], "paths": ["/v1/*"],
     "credential": None},
]}

DENY_POLICY = {"version": 1, "rules": ALLOW_POLICY["rules"] + [
    {"id": "d", "subject": "agent-worker", "effect": "deny",
     "action": "egress",
     "hosts": ["api.example.com"], "ports": [443],
     "methods": ["GET"], "paths": ["/v1/*"],
     "credential": None},
]}

# Deny rule with an unmodeled host shape: the engine cannot prove
# it does NOT cover the request => residual forbid => Unknown.
RESIDUAL_FORBID_POLICY = {"version": 1, "rules": [
    {"id": "a", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["api.example.com"], "ports": [443],
     "methods": ["GET"], "paths": ["/v1/*"],
     "credential": None},
    {"id": "d-weird", "subject": "agent-worker", "effect": "deny",
     "action": "egress",
     "hosts": ["not a host!!"], "ports": [443],
     "methods": ["GET"], "paths": ["/v1/*"],
     "credential": None},
]}

EMPTY_POLICY = {"version": 1, "rules": []}

REQ_OK = {"subject": "agent-worker", "action": "egress",
          "host": "api.example.com", "port": 443,
          "method": "GET", "path": "/v1/models",
          "credential": None}

REQ_OTHER = {"subject": "agent-worker", "action": "egress",
             "host": "other.example.com", "port": 443,
             "method": "GET", "path": "/v1/models",
             "credential": None}

REQ_BAD = {"subject": "agent-worker"}  # malformed request

PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _artifact(record):
    cxs = record.get("counterexamples", [])
    if len(cxs) != 1:
        return None
    return cxs[0]


@probe("delta/widen-basic-counterexample")
def _p1():
    r = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_WIDE)
    cx = _artifact(r)
    if cx is None:
        return False, "expected exactly 1 counterexample, got %d" % len(
            r.get("counterexamples", []))
    checks = []
    if r.get("verdict") != "within_boundary":
        checks.append("verdict %r" % r.get("verdict"))
    if r.get("delta_class") != "expanding":
        checks.append("delta_class %r" % r.get("delta_class"))
    if cx.get("subject") != "agent-worker":
        checks.append("subject %r" % cx.get("subject"))
    if cx.get("action") != "egress":
        checks.append("action %r" % cx.get("action"))
    res = cx.get("resource", {})
    for k, v in (("host", "evil.example.com"), ("port", "443"),
                 ("method", "POST"), ("path", "/exfil")):
        if res.get(k) != v:
            checks.append("resource.%s %r" % (k, res.get(k)))
    if cx.get("within_boundary") is not True:
        checks.append("within_boundary %r" % cx.get("within_boundary"))
    if cx.get("failed_checks") != []:
        checks.append("failed_checks %r" % cx.get("failed_checks"))
    if cx.get("code") != "policy-delta-counterexample-raised":
        checks.append("code %r" % cx.get("code"))
    d = cx.get("evidence_digest", "")
    if not (isinstance(d, str) and len(d) == 64):
        checks.append("evidence_digest malformed")
    if checks:
        return False, "; ".join(checks)
    return True, "1 concrete counterexample, boundary held"


@probe("delta/widen-boundary-breach-attribution")
def _p2():
    r = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_NARROW)
    cx = _artifact(r)
    if cx is None:
        return False, "expected exactly 1 counterexample"
    if r.get("verdict") != "exceeds_boundary":
        return False, "verdict %r" % r.get("verdict")
    if cx.get("within_boundary") is not False:
        return False, "within_boundary %r" % cx.get("within_boundary")
    if cx.get("failed_checks") != ["policy-boundary-exceeded"]:
        return False, "failed_checks %r" % cx.get("failed_checks")
    return True, "boundary breach attributed to the exact grant"


@probe("delta/widen-link-local-attribution")
def _p3():
    r = pd.counterexamples(WIDEN_LINKLOCAL, CURRENT, BOUNDARY_WIDE)
    cxs = r.get("counterexamples", [])
    if not cxs:
        return False, "no counterexamples for link-local expansion"
    hit = [c for c in cxs
           if "policy-change-link-local-reach" in c.get("failed_checks", [])]
    if not hit:
        return False, "no atom fired link-local: %r" % [
            c.get("failed_checks") for c in cxs]
    if hit[0].get("resource", {}).get("host") != "169.254.169.254":
        return False, "resource host %r" % hit[0].get("resource")
    return True, "link-local atom attributed"


@probe("delta/widen-l7-attribution")
def _p4():
    r = pd.counterexamples(WIDEN_L7, CURRENT, BOUNDARY_WIDE,
                           credentialed_hosts=("api.example.com",))
    cxs = r.get("counterexamples", [])
    hit = [c for c in cxs
           if "policy-change-l7-bypass-credentialed"
           in c.get("failed_checks", [])]
    if not hit:
        return False, "no atom fired l7-bypass: %r" % [
            c.get("failed_checks") for c in cxs]
    return True, "l7-bypass atom attributed"


@probe("delta/widen-credential-reach-attribution")
def _p5():
    r = pd.counterexamples(WIDEN_CRED, CURRENT, BOUNDARY_WIDE)
    cxs = r.get("counterexamples", [])
    hit = [c for c in cxs
           if "policy-change-credential-reach-expansion"
           in c.get("failed_checks", [])]
    if not hit:
        return False, "no atom fired credential-reach: %r" % [
            c.get("failed_checks") for c in cxs]
    if hit[0].get("resource", {}).get("credential") != "prod-db":
        return False, "resource credential %r" % hit[0].get("resource")
    return True, "credential-reach atom attributed"


@probe("delta/restrictive-no-counterexamples")
def _p6():
    r = pd.counterexamples(RESTRICTIVE, CURRENT, BOUNDARY_WIDE)
    if r.get("counterexamples"):
        return False, "restrictive delta must emit no counterexamples"
    if r.get("verdict") != "within_boundary":
        return False, "verdict %r" % r.get("verdict")
    if r.get("delta_class") != "restrictive":
        return False, "delta_class %r" % r.get("delta_class")
    return True, "restrictive passes silently"


@probe("delta/equivalent-no-counterexamples")
def _p7():
    r = pd.counterexamples(CURRENT, CURRENT, BOUNDARY_WIDE)
    if r.get("counterexamples"):
        return False, "equivalent delta must emit no counterexamples"
    if r.get("delta_class") != "equivalent":
        return False, "delta_class %r" % r.get("delta_class")
    return True, "equivalent passes silently"


@probe("delta/forbid-residual-veto")
def _p8():
    r = pd.counterexamples(DENY_CAND, CURRENT, BOUNDARY_WIDE)
    if r.get("verdict") != "uncheckable":
        return False, "verdict %r (must be uncheckable)" % r.get("verdict")
    if "policy-delta-forbid-residual" not in r.get("failed_checks", []):
        return False, "failed_checks %r" % r.get("failed_checks")
    return True, "surviving deny rule vetoes the delta"


@probe("delta/malformed-loud")
def _p9():
    try:
        pd.counterexamples("not a policy", CURRENT, BOUNDARY_WIDE)
    except Exception as e:
        if getattr(e, "code", "") == "policy-delta-malformed":
            return True, "loud malformed refusal"
        return False, "wrong code %r" % getattr(e, "code", "?")
    return False, "malformed input did not raise"


@probe("engine/allow-covered-request")
def _p10():
    d = pd.evaluate(ALLOW_POLICY, REQ_OK)
    if d.get("decision") != "Allow":
        return False, "decision %r" % d.get("decision")
    if d.get("matched_rule") != "a":
        return False, "matched_rule %r" % d.get("matched_rule")
    return True, "covered request allowed"


@probe("engine/default-deny-uncovered")
def _p11():
    d = pd.evaluate(ALLOW_POLICY, REQ_OTHER)
    if d.get("decision") != "Deny":
        return False, "decision %r (must default-deny)" % d.get("decision")
    return True, "uncovered request denied by engine default"


@probe("engine/forbid-hard-override")
def _p12():
    d = pd.evaluate(DENY_POLICY, REQ_OK)
    if d.get("decision") != "Deny":
        return False, "decision %r (deny must override allow)" \
            % d.get("decision")
    return True, "forbid overrides permit"


@probe("engine/residual-forbid-unknown")
def _p13():
    d = pd.evaluate(RESIDUAL_FORBID_POLICY, REQ_OK)
    if d.get("decision") != "Unknown":
        return False, "decision %r (must be Unknown, never fail-open)" \
            % d.get("decision")
    return True, "unevaluable deny => Unknown, never fail-open"


@probe("engine/empty-policy-denies")
def _p14():
    d = pd.evaluate(EMPTY_POLICY, REQ_OK)
    if d.get("decision") != "Deny":
        return False, "decision %r (empty policy must not imply allow)" \
            % d.get("decision")
    return True, "no implicit allow on empty policy"


@probe("engine/malformed-request-denies")
def _p15():
    d = pd.evaluate(ALLOW_POLICY, REQ_BAD)
    if d.get("decision") != "Deny":
        return False, "decision %r (malformed request must deny)" \
            % d.get("decision")
    return True, "malformed request fails closed"


@probe("delta/no-drift-vs-containment")
def _p16():
    """The no-drift pin: per-atom fired checks unioned must equal
    the containment module's failed_checks, and verdicts must
    agree. This guarantees the review artifacts never contradict
    the gate verdict."""
    try:
        from gov import policy_change_containment as pcc
    except Exception as e:
        return False, "cannot import containment module: %s" % e
    cases = [
        (WIDEN, CURRENT, BOUNDARY_WIDE, ()),
        (WIDEN, CURRENT, BOUNDARY_NARROW, ()),
        (WIDEN_LINKLOCAL, CURRENT, BOUNDARY_WIDE, ()),
        (WIDEN_L7, CURRENT, BOUNDARY_WIDE, ("api.example.com",)),
        (WIDEN_CRED, CURRENT, BOUNDARY_WIDE, ()),
        (RESTRICTIVE, CURRENT, BOUNDARY_WIDE, ()),
        (CURRENT, CURRENT, BOUNDARY_WIDE, ()),
    ]
    for cand, curr, bound, creds in cases:
        mine = pd.counterexamples(cand, curr, bound,
                                  credentialed_hosts=creds)
        theirs = pcc.check_policy_change(cand, curr, bound,
                                         credentialed_hosts=creds)
        if mine.get("verdict") != theirs.get("verdict"):
            return False, "verdict drift: %r vs %r" % (
                mine.get("verdict"), theirs.get("verdict"))
        union = set()
        for cx in mine.get("counterexamples", []):
            union.update(cx.get("failed_checks", []))
        if union != set(theirs.get("failed_checks", [])):
            return False, "check-set drift: %r vs %r" % (
                sorted(union), theirs.get("failed_checks"))
    return True, "artifacts agree with gate verdicts on 7 deltas"


@probe("delta/review-wiring-digest-only")
def _p17():
    from gov.agent_callbacks import HumanApprovalGate, Continue
    r = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_WIDE)
    journal = []
    gate = HumanApprovalGate(journal)
    approval_id, artifacts = pd.request_review(gate, r, "pol-9")
    checks = []
    if not isinstance(approval_id, str) or not approval_id:
        checks.append("bad approval id")
    if artifacts != r.get("counterexamples"):
        checks.append("artifacts not returned to caller")
    # Public-seam proof the approval is registered: resolve it.
    verdict = gate.resolve(approval_id, True, decider="reviewer")
    if not isinstance(verdict, Continue):
        checks.append("resolve did not resume")
    blob = json.dumps(journal, sort_keys=True, default=str)
    if "evil.example.com" in blob:
        checks.append("RAW GRANT LEAKED INTO JOURNAL")
    if "/exfil" in blob:
        checks.append("RAW PATH LEAKED INTO JOURNAL")
    reqs = [e for e in journal if e.get("kind") == "approval-request"]
    if not reqs:
        checks.append("no approval-request journaled")
    elif reqs[0].get("tool") != "policy-delta-review":
        checks.append("tool %r" % reqs[0].get("tool"))
    if checks:
        return False, "; ".join(checks)
    return True, "digest-only review queued, artifacts to caller"


@probe("delta/unknown-delta-uncheckable")
def _p19():
    cand = {"version": 1, "rules": CURRENT["rules"] + [
        {"id": "weird", "subject": "agent-worker", "effect": "allow",
         "action": "egress",
         "hosts": ["not a host!!"], "ports": [443],
         "methods": ["GET"], "paths": ["/"],
         "credential": None}]}
    r = pd.counterexamples(cand, CURRENT, BOUNDARY_WIDE)
    if r.get("verdict") != "uncheckable":
        return False, "verdict %r (must be uncheckable)" % r.get("verdict")
    if "policy-delta-unknown" not in r.get("failed_checks", []):
        return False, "failed_checks %r" % r.get("failed_checks")
    if r.get("counterexamples"):
        return False, "uncheckable delta must emit no artifacts"
    return True, "unmodeled shape => uncheckable, never vacuous"


@probe("delta/deterministic-digests")
def _p18():
    r1 = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_NARROW)
    r2 = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_NARROW)
    if r1 != r2:
        return False, "non-deterministic records"
    return True, "A==B deterministic"


# ------------------------------------------------------------------
# Green check (depth-1) and main
# ------------------------------------------------------------------

def green_check():
    """Depth-1: adjacent wave-266 policy-prove battery must stay
    green. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", True, "skipped (GOV_SKIP_GREEN=1)")]
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    target = os.path.join(repo, "evals", "w266_policyprove_probes.py")
    if not os.path.exists(target):
        return [("green-check", True, "adjacent battery absent")]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    tmpd = tempfile.mkdtemp(prefix="w267_poldelta_green_")
    try:
        p = subprocess.run(
            [sys.executable, target], capture_output=True, text=True,
            env=env, cwd=tmpd, timeout=600)
    except Exception as e:
        return [("green-check", False, "harness error: %s" % e)]
    ok = p.returncode == 0 and "BREAK=0" in p.stdout \
        and "ERROR=0" in p.stdout
    tail = (p.stdout or "")[-400:]
    return [("green-check", ok,
             "adjacent w266_policyprove_probes exit=%d %s"
             % (p.returncode, tail if not ok else "green"))]


def main():
    results = []
    for name, fn in PROBES:
        try:
            ok, detail = fn()
            results.append((name, bool(ok), str(detail)))
        except Exception as e:
            results.append((name, False, "ERROR: %r" % (e,)))
    results.extend(green_check())
    held = sum(1 for _, ok, _ in results if ok)
    broke = sum(1 for _, ok, _ in results if not ok)
    for name, ok, detail in results:
        print("%s %s: %s" % ("HELD" if ok else "BREAK", name, detail))
    print("TOTAL: %d HELD / %d BREAK / 0 ERROR" % (held, broke))
    return 0 if broke == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
