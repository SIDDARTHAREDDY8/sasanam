"""Break-first F219 closure battery: no raw RecursionError may escape
any public gov/approval_policy.py seam.

Wave-257 lane 3 (F219 closure). Stdlib only. Deterministic across runs
(staging + `env -u GOV_DEPLOYMENT_MODE`).

F219 (LOW, OPEN at write time): _request_digest() catches only
(TypeError, ValueError) around json.dumps, and _check_predicate()
recurses on the and/or/not predicate structure -- a deeply-nested
request (route/simulate) or predicate (compile_rules) escapes raw
RecursionError instead of an ApprovalPolicyError machine code. Same
defect class as F218 (bounded at 200 + defensive catch there).

Close-when (from FINDINGS.md): (1) route(), simulate(), and
compile_rules() refuse deeply-nested inputs with an
ApprovalPolicyError machine code -- no raw RecursionError escapes;
(2) these three probes BREAK (raw RecursionError) on the old code
and HELD (machine-coded refusal) on the fixed code, in both staging
and `env -u GOV_DEPLOYMENT_MODE`; (3) adjacent suites green.

Method (diagnosing-bugs skill): each probe is falsifiable. Verdicts:
HELD (machine-coded refusal) or BREAK (raw exception or acceptance).
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import approval_policy as ap  # noqa: E402
from gov import decision_codes  # noqa: E402  (taxonomy pin below)

TAXONOMY_PIN = 2044 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)




def _held(detail=""):
    return ("HELD", detail)


def _break(detail=""):
    return ("BREAK", detail)


def _deep_dict(depth):
    deep = {"leaf": 1}
    for _ in range(depth):
        deep = {"n": deep}
    return deep


_DEEP = 12000  # json.dumps raises RecursionError at ~10000 here.


def _deep_request():
    return {"kind": "x", "payload": _deep_dict(_DEEP)}


def _auto_rules():
    return ap.compile_rules({
        "version": 1,
        "rules": [{
            "id": "r-auto",
            "when": {"field": "kind", "op": "eq", "value": "x"},
            "action": "auto-approve",
        }],
    })


def _route_deep():
    # F219: route() digests the request; raw RecursionError escapes
    # the public routing seam instead of an ApprovalPolicyError.
    rs = _auto_rules()
    try:
        ap.route(rs, _deep_request(), audit_sink=lambda entry: None)
    except RecursionError:
        return _break("raw RecursionError escaped route()")
    except ap.ApprovalPolicyError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep request routed")


def _simulate_deep():
    # F219: simulate() digests every request; raw RecursionError
    # escapes the read-only preview seam too.
    rs = _auto_rules()
    try:
        ap.simulate(rs, [_deep_request()])
    except RecursionError:
        return _break("raw RecursionError escaped simulate()")
    except ap.ApprovalPolicyError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("deep request simulated")


def _compile_deep_predicate():
    # F219: _check_predicate recurses on and/or structure; a
    # deeply-nested predicate escapes raw RecursionError from the
    # compile seam instead of approval-policy-malformed.
    pred = {"field": "a", "op": "eq", "value": 1}
    for _ in range(_DEEP):
        pred = {"and": [pred]}
    doc = {"version": 1, "rules": [{
        "id": "r-deep", "when": pred, "action": "require-approval"}]}
    try:
        ap.compile_rules(doc)
    except RecursionError:
        return _break("raw RecursionError escaped compile_rules()")
    except ap.ApprovalPolicyError as exc:
        return _held("machine-coded refusal %s" % exc.code)
    except Exception as exc:
        return _break("raw %s escaped" % type(exc).__name__)
    return _break("pathological predicate compiled")


PROBES = [_route_deep, _simulate_deep, _compile_deep_predicate]


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_approval_policy"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g257-f219-green"
    os.makedirs(td, exist_ok=True)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: test_approval_policy green")
    return True


def main():
    assert len(decision_codes.TAXONOMY) == TAXONOMY_PIN, (
        "taxonomy pin: expected %d, got %d"
        % (TAXONOMY_PIN, len(decision_codes.TAXONOMY)))
    held, broken = 0, 0
    for fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 -- probe harness
            verdict, detail = ("ERROR", "%r" % (exc,))
        if verdict == "HELD":
            held += 1
        else:
            broken += 1
        print("%-32s %-6s %s" % (fn.__name__, verdict, detail))
    ok = green_check()
    print("probes=%d held=%d broken=%d green=%s"
          % (len(PROBES), held, broken, "OK" if ok else "FAIL"))
    return 0 if (broken == 0 and ok) else 1


if __name__ == "__main__":
    sys.exit(main())
