"""Break-first red-team battery for the policy-delta x exception-tuple
composition (wave-269 composition lane).

Closes the wave-268 red-team forward hazard ``poldelta/exception-skip-
forward``: the request engine had no skip/exception concept, so a
RuleSkip could in principle clear a deny or an Unknown. This battery
pins the composition contract on gov/policy_delta.py:

  evaluate:  Deny > Unknown > Allow, structurally.
    - a granted skip on an ALLOW rule suppresses that rule's grant
      (recorded with exception identity; engine default-deny decides)
    - a granted skip on a DENY rule is recorded as VETOED and the
      deny stands (deny-veto is structural, never a named operator)
    - a residual (unevaluable) deny yields Unknown regardless of any
      skip (residual-deny => Unknown is structural)
    - exception expiry is evaluated against the pinned eval_start:
      an expired exception re-arms the rule automatically
  counterexamples: expansion grants are never dropped by skips; a
    grant whose rule is exception-skipped is emitted WITH the
    exception identity attached (auditable by construction).

Method (diagnosing-bugs skill): each probe is a falsifiable break
attempt against a PUBLIC seam. On the unmodified wave-268 tree the
composition seam does not exist, so the probes fail (TypeError on the
new kwargs) -- the hazard is real. After the composition lands every
probe must HELD, in staging and under `env -u GOV_DEPLOYMENT_MODE`.

Stdlib only. Deterministic. No in-repo git subprocesses (wave-36
supply-chain probe: fail closed). Green checks are depth-1 and honor
GOV_SKIP_GREEN=1.
"""

import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

from gov import policy_delta as pd
from gov import policy_exception as pe
from gov import ed25519
from gov.signing import Ed25519Verifier

TAXONOMY_PIN = 1769  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

EVAL_START = "2026-10-01T12:00:00Z"
POLICY_NAME = "delta-policy"

# ------------------------------------------------------------------
# Fixtures (policy shapes follow evals/w267_poldelta_probes.py).
# ------------------------------------------------------------------

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

DENY_CAND = {"version": 1, "rules": CURRENT["rules"] + [
    {"id": "deny-x", "subject": "agent-worker", "effect": "deny",
     "action": "egress",
     "hosts": ["*"], "ports": [443],
     "methods": ["*"], "paths": ["*"],
     "credential": None},
]}

BOUNDARY_WIDE = {"version": 1, "rules": [
    {"id": "b", "subject": "agent-worker", "effect": "allow",
     "action": "egress",
     "hosts": ["*.example.com"], "ports": [443],
     "methods": ["GET", "POST"], "paths": ["*"],
     "credential": None},
]}

REQ_OK = {"subject": "agent-worker", "action": "egress",
          "host": "api.example.com", "port": 443,
          "method": "GET", "path": "/v1/models",
          "credential": None}


# ------------------------------------------------------------------
# Test signing material (deployment-owned keys, test-local only).
# ------------------------------------------------------------------

def _keys(keyid="test-key-1"):
    seed = ed25519.generate_seed()
    return {"seed": seed, "pub": ed25519.publickey(seed),
            "keyid": keyid}


def _wire(keys, exc_id, rule_names, expires_at="2027-01-01T00:00:00Z"):
    body = {
        "kind": "sasanam.policy-exception/v1",
        "id": exc_id,
        "policyName": POLICY_NAME,
        "ruleNames": list(rule_names),
        "match": {"any": [
            {"path": "subject", "op": "eq", "value": "agent-worker"}]},
        "conditions": [],
        "expiresAt": expires_at,
        "compensatingValidations": [],
    }
    return pe.seal_exception(body, keys["seed"], keys["keyid"])


def _loaded(keys, wires):
    trusted = {keys["keyid"]: Ed25519Verifier(keys["pub"],
                                              keys["keyid"])}
    return pe.load_exceptions(wires, trusted, EVAL_START).exceptions


def _seam(exceptions, policy_name=POLICY_NAME, eval_start=EVAL_START):
    return {"exceptions": exceptions, "policy_name": policy_name,
            "eval_start": eval_start}


PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


# ------------------------------------------------------------------
# The hazard pin: on the unmodified tree this seam does not exist.
# ------------------------------------------------------------------

@probe("seam/hazard-present")
def _p0():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-allow-1", ["a"])])
    try:
        d = pd.evaluate(ALLOW_POLICY, REQ_OK, **_seam(excs))
    except TypeError as e:
        return False, "seam absent (TypeError: %s)" % (e,)
    if not isinstance(d, dict) or "decision" not in d:
        return False, "bad decision record %r" % (d,)
    return True, "composition seam exists"


# ------------------------------------------------------------------
# evaluate: skip must never clear a deny.
# ------------------------------------------------------------------

@probe("engine/skip-on-deny-still-denies")
def _p1():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-deny-1", ["d"])])
    d = pd.evaluate(DENY_POLICY, REQ_OK, **_seam(excs))
    checks = []
    if d.get("decision") != "Deny":
        checks.append("decision %r (deny-veto must hold)" %
                      d.get("decision"))
    if d.get("reason") != "policy-delta-forbid":
        checks.append("reason %r" % d.get("reason"))
    if d.get("matched_rule") != "d":
        checks.append("matched_rule %r" % d.get("matched_rule"))
    skips = d.get("exception_skips", [])
    if len(skips) != 1:
        checks.append("exception_skips %r (vetoed skip must be "
                      "attributed, never silently dropped)" % (skips,))
    else:
        s = skips[0]
        if s.get("rule") != "d" or s.get("vetoed") is not True:
            checks.append("skip entry %r" % (s,))
        if s.get("exception_ids") != ["exc-deny-1"]:
            checks.append("exception_ids %r" % s.get("exception_ids"))
        if s.get("code") != "exception-granted-with-attribution":
            checks.append("code %r" % s.get("code"))
    if checks:
        return False, "; ".join(checks)
    return True, "deny-veto holds; vetoed skip attributed"


# ------------------------------------------------------------------
# evaluate: skip must never convert Unknown to Allow.
# ------------------------------------------------------------------

@probe("engine/skip-on-unknown-stays-unknown")
def _p2():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-allow-1", ["a"])])
    d = pd.evaluate(RESIDUAL_FORBID_POLICY, REQ_OK, **_seam(excs))
    if d.get("decision") != "Unknown":
        return False, "decision %r (residual forbid => Unknown, " \
            "never Allow)" % d.get("decision")
    if d.get("reason") != "policy-delta-forbid-residual":
        return False, "reason %r" % d.get("reason")
    return True, "residual-deny => Unknown survives skipping"


# ------------------------------------------------------------------
# evaluate: skip suppresses an allow grant; default-deny decides.
# ------------------------------------------------------------------

@probe("engine/skip-on-allow-suppresses-grant")
def _p3():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-allow-1", ["a"])])
    d = pd.evaluate(ALLOW_POLICY, REQ_OK, **_seam(excs))
    checks = []
    if d.get("decision") != "Deny":
        checks.append("decision %r (suppressed grant must not Allow)"
                      % d.get("decision"))
    if d.get("reason") != "policy-delta-default-deny":
        checks.append("reason %r" % d.get("reason"))
    if d.get("matched_rule") is not None:
        checks.append("matched_rule %r" % d.get("matched_rule"))
    skips = d.get("exception_skips", [])
    if len(skips) != 1 or skips[0].get("rule") != "a" or\
            skips[0].get("vetoed") is not False or\
            skips[0].get("exception_ids") != ["exc-allow-1"]:
        checks.append("exception_skips %r" % (skips,))
    if checks:
        return False, "; ".join(checks)
    return True, "allow grant suppressed, skip attributed"


@probe("engine/no-exception-control")
def _p4():
    d = pd.evaluate(ALLOW_POLICY, REQ_OK)
    checks = []
    if d.get("decision") != "Allow":
        checks.append("decision %r" % d.get("decision"))
    if d.get("matched_rule") != "a":
        checks.append("matched_rule %r" % d.get("matched_rule"))
    if d.get("exception_skips") != []:
        checks.append("exception_skips %r" % d.get("exception_skips"))
    if checks:
        return False, "; ".join(checks)
    return True, "no-exception behavior unchanged"


# ------------------------------------------------------------------
# Expiry: an expired exception re-arms the rule.
# ------------------------------------------------------------------

@probe("engine/expired-exception-rearms-allow")
def _p5():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-old-1", ["a"],
                                expires_at="2020-01-01T00:00:00Z")])
    d = pd.evaluate(ALLOW_POLICY, REQ_OK, **_seam(excs))
    checks = []
    if d.get("decision") != "Allow":
        checks.append("decision %r (expired exception must not "
                      "suppress)" % d.get("decision"))
    if d.get("matched_rule") != "a":
        checks.append("matched_rule %r" % d.get("matched_rule"))
    if d.get("exception_skips") != []:
        checks.append("exception_skips %r" % d.get("exception_skips"))
    if checks:
        return False, "; ".join(checks)
    return True, "expired exception re-arms the allow rule"


@probe("engine/expired-exception-deny-veto-active")
def _p6():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-old-2", ["d"],
                                expires_at="2020-01-01T00:00:00Z")])
    d = pd.evaluate(DENY_POLICY, REQ_OK, **_seam(excs))
    if d.get("decision") != "Deny" or\
            d.get("reason") != "policy-delta-forbid":
        return False, "decision %r (deny-veto active again)" % (d,)
    if d.get("exception_skips") != []:
        return False, "exception_skips %r" % d.get("exception_skips")
    return True, "expired exception re-arms the deny veto"


# ------------------------------------------------------------------
# Seam discipline: no silent clocks, no inert-but-noisy seams.
# ------------------------------------------------------------------

@probe("engine/exception-inert-without-policy-name")
def _p7():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-allow-1", ["a"])])
    d = pd.evaluate(ALLOW_POLICY, REQ_OK,
                    **_seam(excs, policy_name=None))
    if d.get("decision") != "Allow":
        return False, "decision %r (exceptions without a policy name " \
            "must be inert, fail-closed toward enforcement)" %\
            d.get("decision")
    return True, "nameless exceptions are inert"


@probe("engine/exceptions-require-eval-start")
def _p8():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-allow-1", ["a"])])
    try:
        pd.evaluate(ALLOW_POLICY, REQ_OK,
                    **_seam(excs, eval_start=None))
    except Exception as e:
        if getattr(e, "code", "") == "policy-delta-malformed":
            return True, "loud malformed refusal (no silent clock)"
        return False, "wrong code %r" % getattr(e, "code", "?")
    return False, "missing eval_start did not raise"


# ------------------------------------------------------------------
# counterexamples: skipped rules are attributed, never dropped.
# ------------------------------------------------------------------

@probe("delta/counterexample-skip-attribution")
def _p9():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-evil-1", ["llm-evil"])])
    r = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_WIDE, **_seam(excs))
    cxs = r.get("counterexamples", [])
    if len(cxs) != 1:
        return False, "expected exactly 1 counterexample (grant must " \
            "not be silently dropped), got %d" % len(cxs)
    cx = cxs[0]
    skips = cx.get("exception_skips", [])
    if len(skips) != 1 or skips[0].get("rule") != "llm-evil" or\
            skips[0].get("exception_ids") != ["exc-evil-1"]:
        return False, "exception_skips %r (skipped rule must appear " \
            "with its exception identity)" % (skips,)
    if cx.get("resource", {}).get("host") != "evil.example.com":
        return False, "grant misattributed: %r" % (cx.get("resource"),)
    return True, "skipped grant attributed with exception identity"


@probe("delta/counterexample-no-skip-control")
def _p10():
    r = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_WIDE)
    cxs = r.get("counterexamples", [])
    if len(cxs) != 1:
        return False, "expected 1 counterexample, got %d" % len(cxs)
    if "exception_skips" in cxs[0]:
        return False, "no-skip record must not carry exception_skips"
    return True, "no-exception records byte-identical to before"


@probe("delta/deny-veto-survives-skip")
def _p11():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-denyx-1", ["deny-x"])])
    r = pd.counterexamples(DENY_CAND, CURRENT, BOUNDARY_WIDE,
                           **_seam(excs))
    if r.get("verdict") != "uncheckable":
        return False, "verdict %r (deny veto must survive skipping)"\
            % r.get("verdict")
    if "policy-delta-forbid-residual" not in r.get("failed_checks", []):
        return False, "failed_checks %r" % r.get("failed_checks")
    return True, "forbid veto survives exception skipping"


# ------------------------------------------------------------------
# Taxonomy: this composition mints no new codes.
# ------------------------------------------------------------------

@probe("meta/no-new-codes")
def _p12():
    from gov import decision_codes as dc
    if len(dc.TAXONOMY) != TAXONOMY_PIN:
        return False, "registry has %d entries (pin %d)" % (
            len(dc.TAXONOMY), TAXONOMY_PIN)
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-deny-1", ["d"])])
    d = pd.evaluate(DENY_POLICY, REQ_OK, **_seam(excs))
    codes = {d.get("reason")}
    for s in d.get("exception_skips", []):
        codes.add(s.get("code"))
    unknown = [c for c in codes if c not in dc.TAXONOMY]
    if unknown:
        return False, "unregistered codes %r" % (unknown,)
    return True, "all codes registered; pin %d holds" % TAXONOMY_PIN


@probe("meta/deterministic")
def _p13():
    keys = _keys()
    excs = _loaded(keys, [_wire(keys, "exc-allow-1", ["a"])])
    d1 = pd.evaluate(ALLOW_POLICY, REQ_OK, **_seam(excs))
    d2 = pd.evaluate(ALLOW_POLICY, REQ_OK, **_seam(excs))
    if d1 != d2:
        return False, "non-deterministic decision records"
    r1 = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_WIDE,
                            **_seam(excs))
    r2 = pd.counterexamples(WIDEN, CURRENT, BOUNDARY_WIDE,
                            **_seam(excs))
    if r1 != r2:
        return False, "non-deterministic counterexample records"
    return True, "A==B deterministic"


# ------------------------------------------------------------------
# Green check (depth-1) and main
# ------------------------------------------------------------------

def green_check():
    """Depth-1: adjacent poldelta + exception batteries stay green.
    Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-check", True, "skipped (GOV_SKIP_GREEN=1)")]
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    targets = [
        ("w267_poldelta_probes.py", "0 BREAK"),
        ("w268_exception_probes.py", "RESULT FAIL"),
    ]
    out = []
    for fname, green_marker in targets:
        target = os.path.join(repo, "evals", fname)
        if not os.path.exists(target):
            out.append(("green-check:" + fname, True,
                        "adjacent battery absent"))
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        tmpd = tempfile.mkdtemp(prefix="w269_skip_green_")
        try:
            p = subprocess.run(
                [sys.executable, target], capture_output=True, text=True,
                env=env, cwd=tmpd, timeout=600)
        except Exception as e:
            out.append(("green-check:" + fname, False,
                        "harness error: %s" % e))
            continue
        if fname == "w268_exception_probes.py":
            ok = p.returncode == 0 and green_marker not in p.stdout
        else:
            ok = p.returncode == 0 and green_marker in p.stdout
        tail = (p.stdout or "")[-300:]
        out.append(("green-check:" + fname, ok,
                    "exit=%d %s" % (p.returncode,
                                    "green" if ok else tail)))
    return out


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
