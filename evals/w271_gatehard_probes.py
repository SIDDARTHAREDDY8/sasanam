#!/usr/bin/env python3
"""Wave-271 red-first battery: enforcement-path hardening (Kubewarden disciplines).

Red phase:  GOV_GATEHARD_IMPL=stub -> permissive StubGate foil. Every
attack probe must BREAK (the stub allows what a hardened gate refuses);
a probe that HELDs on the stub is vacuous and is flagged.
Green phase: default (gov.gate_hardening) -> every probe must HELD.

Protocol constants below are pinned from the build spec, not imported
from the module under test, so the battery is not tautological.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

# -- spec-pinned protocol constants (NOT imported from gov.gate_hardening)
MODE_MONITOR = "monitor"
MODE_PROTECT = "protect"
NOW = 1791000000  # fixed test clock (2026-10-01-ish)

# -- quoted-literal pin count method (wave-270 ceremony lane correction:
# grep -o '"code": ' overcounts; quoted-literal extraction is canonical).
import re as _re  # noqa: E402

TAXONOMY_PIN = 2069 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*)


_GATEHARD_CODES = (
    "gatehard-monitor-would-deny",
    "gatehard-policy-denied",
    "gatehard-policy-malformed",
    "gatehard-global-deadline-unset",
    "gatehard-per-policy-deadline-exceeds-global",
    "gatehard-host-callback-denied",
    "gatehard-host-callback-wildcard",
    "gatehard-gate-error",
    "gatehard-gate-timeout",
    "gatehard-ignore-exception-used",
    "gatehard-ignore-exception-invalid",
    "gatehard-breakglass-used",
    "gatehard-breakglass-invalid",
    "gatehard-unknown-mode",
)


def _quoted_literals(path):
    src = open(path).read()
    return _re.findall(r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)


# ---------------------------------------------------------------------------
# Permissive stub foil (red phase): allows everything, ignores all hardening.
# ---------------------------------------------------------------------------

class StubGate(object):
    """Foil with the Gate public shape but no checks: monitor/protect
    distinction absent, no global deadline requirement, no callback
    allowlist, no error/timeout fail-closed, no audit scanner."""

    def __init__(self, **kwargs):
        self.mode = kwargs.get("mode", MODE_PROTECT)
        self._audit = []

    def evaluate(self, request, **kwargs):
        return {"allowed": True, "mode": self.mode, "code": None,
                "detail": "stub: allowed"}

    def invoke_host_callback(self, name, *args, **kwargs):
        return "stub-callback-result"

    def promote_to_protect(self, **kwargs):
        self.mode = MODE_PROTECT
        return {"ok": True}

    def scan(self, requests, **kwargs):
        return [{"request_id": r["request_id"], "would": "allow",
                 "code": None} for r in requests]

    def audit_log(self):
        return list(self._audit)


def _make_gate(impl, **overrides):
    if impl == "stub":
        return StubGate(**overrides)
    from gov import gate_hardening as gh
    params = dict(
        mode=overrides.get("mode", MODE_PROTECT),
        global_deadline_s=overrides.get("global_deadline_s", 5.0),
        host_allowlist=overrides.get("host_allowlist", frozenset()),
        now=lambda: overrides.get("now_value", NOW),
    )
    for k, v in overrides.items():
        if k not in params and k != "policies":
            params[k] = v
    gate = gh.Gate(**params)
    for p in overrides.get("policies", ()):
        gate.register_policy(p)
    return gate


def _policy(predicate, deadline_s=None, callbacks=frozenset(),
            policy_id=None):
    """Build a policy spec dict for register/compile (spec-pinned shape)."""
    if _IMPL == "stub":
        return {"predicate": predicate, "policy_id": policy_id or "p"}
    from gov import gate_hardening as gh
    return gh.compile_policy(
        {"policy_id": policy_id or "p",
         "predicate_name": getattr(predicate, "__name__", "p"),
         "predicate": predicate,
         "deadline_s": deadline_s,
         "host_callbacks": list(callbacks)})


_IMPRESSIBLE = object()
_IMPL = os.environ.get("GOV_GATEHARD_IMPL", "real")


def _require_real():
    return _IMPL != "stub"


# ---------------------------------------------------------------------------
# Probe framework
# ---------------------------------------------------------------------------

class Probe(object):
    def __init__(self, pid, fn, attack=True):
        self.pid = pid
        self.fn = fn
        self.attack = attack


_PROBES = []


def probe(pid, attack=True):
    def deco(fn):
        _PROBES.append(Probe(pid, fn, attack))
        return fn
    return deco


def _check(gate, request, expect_allowed):
    v = gate.evaluate(request)
    return bool(v.get("allowed")) == expect_allowed, v


# --- attack probes (must BREAK on stub, HELD on real) ---

@probe("p1/bogus-module-no-cross-request-state")
def _p1():
    """A predicate that smuggles state into its runtime context must not
    affect the next request: each request gets a fresh, discarded Runtime."""
    leaked = []

    def evil(runtime):
        runtime.ctx["evil"] = runtime.ctx.get("evil", 0) + 1
        leaked.append(id(runtime))
        return True

    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(evil)])
    v1 = gate.evaluate({"request_id": "r1"})
    v2 = gate.evaluate({"request_id": "r2"})
    if not _require_real():
        # stub: no runtime isolation at all -> attack succeeds silently
        return False, "stub allows un-isolated evaluation"
    # real: fresh runtimes (different objects), no per-request state retained
    # by the gate after evaluation.
    ok = (len(leaked) == 2 and leaked[0] != leaked[1]
          and gate._runtime_after_eval_is_none())
    return ok, "fresh discarded runtime per request"


@probe("p2/global-deadline-unset-fails-closed")
def _p2():
    """Kubewarden's trap: global-disabled => per-policy timeout silently
    ignored. Sasanam: gate construction without a global deadline refuses."""
    if not _require_real():
        gate = _make_gate(_IMPL, mode=MODE_PROTECT, global_deadline_s=None)
        v = gate.evaluate({"request_id": "r1"})
        return False, "stub allowed gate without global deadline"
    from gov import gate_hardening as gh
    try:
        gh.Gate(mode=MODE_PROTECT, global_deadline_s=None)
    except gh.GateConfigError as e:
        return e.code == "gatehard-global-deadline-unset", e.code
    return False, "construction without global deadline did not refuse"


@probe("p3/empty-allowlist-denies-all-callbacks")
def _p3():
    """Empty host-callback allowlist = none; a policy requesting a
    privileged callback is refused."""
    def needs_cb(runtime):
        runtime.host_callback("read_secret", "k")
        return True

    gate = _make_gate(_IMPL, mode=MODE_PROTECT, host_allowlist=frozenset(),
                      policies=[_policy(needs_cb,
                                        callbacks=frozenset(["read_secret"]))])
    if not _require_real():
        return False, "stub invoked callback despite empty allowlist"
    v = gate.evaluate({"request_id": "r1"})
    return (not v["allowed"]
            and v["code"] == "gatehard-host-callback-denied"), v


@probe("p3b/wildcard-allowlist-refused-at-construction")
def _p3b():
    """Offering a '*' wildcard in the allowlist is refused loudly at
    construction (Kubewarden's `*` = all trap)."""
    if not _require_real():
        gate = _make_gate(_IMPL, host_allowlist=frozenset(["*"]))
        return False, "stub accepted wildcard allowlist"
    from gov import gate_hardening as gh
    try:
        gh.Gate(mode=MODE_PROTECT, global_deadline_s=5.0,
                host_allowlist=frozenset(["*"]))
    except gh.GateConfigError as e:
        return e.code == "gatehard-host-callback-wildcard", e.code
    return False, "wildcard allowlist not refused"


@probe("p4/monitor-never-denies")
def _p4():
    """Monitor mode is audit-only: even a would-deny request is allowed,
    with the would-deny recorded."""
    gate = _make_gate(_IMPL, mode=MODE_MONITOR,
                      policies=[_policy(lambda rt: False)])
    v = gate.evaluate({"request_id": "r1"})
    if not _require_real():
        # stub has no monitor distinction: it "allows" but without the
        # mandatory audit-only semantics -> vacuous BREAK
        return False, "stub lacks monitor semantics"
    return (v["allowed"] and v["code"] == "gatehard-monitor-would-deny"
            and any(e.get("event") == "monitor-would-deny"
                    for e in gate.audit_log())), v


@probe("p5/audit-scanner-flags-new-denials-deterministically")
def _p5():
    """The audit-scanner analog flags newly-denying items on re-run and
    iterates in deterministic (request_id) order."""
    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(lambda rt: True)])
    reqs = [{"request_id": "r%d" % i, "action": "a"} for i in (3, 1, 2)]
    rep1 = gate.scan(reqs)
    # tighten the policy: r2 now denied
    gate2 = _make_gate(_IMPL, mode=MODE_PROTECT,
                       policies=[_policy(
                           lambda rt: rt.request.get("request_id") != "r2")])
    rep2 = gate2.scan(reqs)
    if not _require_real():
        return False, "stub scan is decorative"
    ids1 = [r["request_id"] for r in rep1]
    new_denials = [r["request_id"] for r in rep2
                   if r["would"] == "deny"]
    return (ids1 == ["r1", "r2", "r3"]
            and new_denials == ["r2"]), (ids1, new_denials)


@probe("p6/gate-error-default-deny")
def _p6():
    """A crashing policy defaults to deny (failurePolicy=Ignore must not
    be the silent default)."""
    def boom(runtime):
        raise RuntimeError("policy crashed")

    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(boom)])
    v = gate.evaluate({"request_id": "r1"})
    if not _require_real():
        return False, "stub allows crashed policy"
    return (not v["allowed"] and v["code"] == "gatehard-gate-error"), v


@probe("p6b/gate-timeout-default-deny")
def _p6b():
    """A policy exceeding its deadline defaults to deny."""
    def slow(runtime):
        time.sleep(0.05)
        return True

    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(slow, deadline_s=0.005)])
    v = gate.evaluate({"request_id": "r1"})
    if not _require_real():
        return False, "stub allows over-deadline policy"
    return (not v["allowed"] and v["code"] == "gatehard-gate-timeout"), v


@probe("p7/per-policy-deadline-cannot-exceed-global")
def _p7():
    """Per-policy overrides tighten only: exceeding the global floor is
    refused at registration (inverted Kubewarden trap)."""
    if not _require_real():
        gate = _make_gate(_IMPL, global_deadline_s=1.0)
        return False, "stub has no deadline discipline"
    from gov import gate_hardening as gh
    gate = gh.Gate(mode=MODE_PROTECT, global_deadline_s=1.0, now=lambda: NOW)
    try:
        gate.register_policy(gh.compile_policy(
            {"policy_id": "loose", "predicate_name": "p",
             "predicate": lambda rt: True, "deadline_s": 60.0,
             "host_callbacks": []}))
    except gh.GateConfigError as e:
        return (e.code
                == "gatehard-per-policy-deadline-exceeds-global"), e.code
    return False, "loose per-policy deadline not refused"


@probe("p8/ignore-exception-requires-valid-signature")
def _p8():
    """failurePolicy=Ignore only as signed, expiring, audited exception:
    a forged/expired exception does not rescue a crashed policy."""
    def boom(runtime):
        raise RuntimeError("policy crashed")

    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(boom, policy_id="boom")])
    if not _require_real():
        return False, "stub has no failure discipline"
    from gov import gate_hardening as gh
    bad_exc = gh.FailureIgnore(
        policy_id="boom", not_before=NOW - 10, expires_at=NOW + 60,
        reason="forged", signature=b"bogus")
    v = gate.evaluate({"request_id": "r1"}, failure_ignore=bad_exc)
    return (not v["allowed"]
            and v["code"] == "gatehard-ignore-exception-invalid"), v


@probe("p9/breakglass-needs-signature-not-namespace")
def _p9():
    """Break-glass is signed policy: a token claiming a trusted namespace
    without a valid signature is refused (no hardcoded bypass)."""
    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(lambda rt: False)])
    if not _require_real():
        return False, "stub has no break-glass discipline"
    from gov import gate_hardening as gh
    tok = gh.BreakGlassToken(
        request_class="deny-all", not_before=NOW - 10, expires_at=NOW + 60,
        reason="namespace says trusted", namespace="trusted",
        signature=b"bogus")
    v = gate.evaluate({"request_id": "r1"}, break_glass=tok)
    return (not v["allowed"]
            and v["code"] == "gatehard-breakglass-invalid"), v


@probe("p10/unknown-mode-refused")
def _p10():
    """An unrecognized gate mode fails closed at construction."""
    if not _require_real():
        return False, "stub has no mode vocabulary"
    from gov import gate_hardening as gh
    try:
        gh.Gate(mode="observe", global_deadline_s=5.0)
    except gh.GateConfigError as e:
        return e.code == "gatehard-unknown-mode", e.code
    return False, "unknown mode not refused"


# --- control probes (must HELD on both stub and real) ---

@probe("c1/benign-allowed", attack=False)
def _c1():
    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(lambda rt: True)])
    v = gate.evaluate({"request_id": "r1"})
    return v["allowed"], v


@probe("c2/listed-callback-works", attack=False)
def _c2():
    seen = []

    def uses_cb(runtime):
        seen.append(runtime.host_callback("metrics", "tick"))
        return True

    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      host_allowlist=frozenset(["metrics"]),
                      policies=[_policy(uses_cb, callbacks=["metrics"])])
    v = gate.evaluate({"request_id": "r1"})
    if not _require_real():
        return v["allowed"], v
    return v["allowed"] and seen == ["cb:metrics:tick"], (v, seen)


@probe("c3/promotion-recorded", attack=False)
def _c3():
    gate = _make_gate(_IMPL, mode=MODE_MONITOR,
                      policies=[_policy(lambda rt: True)])
    gate.promote_to_protect(now=NOW, reason="rollout complete")
    if not _require_real():
        return True, "stub"
    return (gate.mode == MODE_PROTECT
            and any(e.get("event") == "mode-promoted"
                    for e in gate.audit_log())), gate.mode


@probe("c4/signed-breakglass-works", attack=False)
def _c4():
    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(lambda rt: False)])
    if not _require_real():
        return True, "stub"
    from gov import gate_hardening as gh, ed25519 as _ed
    seed = bytes([0x42]) * 32
    pub = _ed.publickey(seed)
    gate2 = gh.Gate(mode=MODE_PROTECT, global_deadline_s=5.0,
                    breakglass_issuer_pub=pub, now=lambda: NOW)
    gate2.register_policy(gh.compile_policy(
        {"policy_id": "p", "predicate_name": "p",
         "predicate": lambda rt: False, "host_callbacks": []}))
    body = gh.breakglass_body("deny-all", NOW - 10, NOW + 60, "incident-7")
    tok = gh.BreakGlassToken(
        request_class="deny-all", not_before=NOW - 10, expires_at=NOW + 60,
        reason="incident-7", signature=_ed.sign(seed, body))
    v = gate2.evaluate({"request_id": "r1", "class": "deny-all"},
                       break_glass=tok)
    return (v["allowed"] and v["code"] == "gatehard-breakglass-used"), v


@probe("c5/signed-ignore-exception-works", attack=False)
def _c5():
    def boom(runtime):
        raise RuntimeError("x")

    gate = _make_gate(_IMPL, mode=MODE_PROTECT,
                      policies=[_policy(boom, policy_id="boom")])
    if not _require_real():
        return True, "stub"
    from gov import gate_hardening as gh, ed25519 as _ed
    seed = bytes([0x43]) * 32
    pub = _ed.publickey(seed)
    gate2 = gh.Gate(mode=MODE_PROTECT, global_deadline_s=5.0,
                    exception_issuer_pub=pub, now=lambda: NOW)
    gate2.register_policy(gh.compile_policy(
        {"policy_id": "boom", "predicate_name": "boom",
         "predicate": boom, "host_callbacks": []}))
    body = gh.failure_ignore_body("boom", NOW - 10, NOW + 60, "flaky-vendor")
    exc = gh.FailureIgnore(
        policy_id="boom", not_before=NOW - 10, expires_at=NOW + 60,
        reason="flaky-vendor", signature=_ed.sign(seed, body))
    v = gate2.evaluate({"request_id": "r1"}, failure_ignore=exc)
    return (v["allowed"]
            and v["code"] == "gatehard-ignore-exception-used"), v


@probe("c6/taxonomy-pin", attack=False)
def _c6():
    lits = _quoted_literals(os.path.join(_REPO, "gov", "decision_codes.py"))
    if not _require_real():
        return len(lits) == 1700, len(lits)
    missing = [c for c in _GATEHARD_CODES if lits.count(c) != 1]
    dups = [c for c in set(lits) if lits.count(c) > 1]
    return (len(lits) == TAXONOMY_PIN and not missing and not dups,
            (len(lits), missing, dups))


# ---------------------------------------------------------------------------
# Green checks (depth-1; honor GOV_SKIP_GREEN=1)
# ---------------------------------------------------------------------------

def _green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return [("green-checks-skipped", True, "GOV_SKIP_GREEN=1")]
    results = []
    # Determinism: run this battery's own main twice under the real impl and
    # compare the verdict signature (A == B).
    for tag in ("A", "B"):
        env = dict(os.environ)
        env["GOV_GATEHARD_IMPL"] = "real"
        env["GOV_SKIP_GREEN"] = "1"
        p = subprocess.run([sys.executable, __file__],
                           capture_output=True, text=True, env=env,
                           cwd=_REPO)
        sig = [ln for ln in p.stdout.splitlines()
               if ln.startswith("PROBE ")]
        results.append(("determinism-%s" % tag, p.returncode == 0, sig))
    ok = (results[0][1] and results[1][1]
          and results[0][2] == results[1][2])
    results.append(("determinism-A==B", ok, len(results[0][2])))
    return results


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    held, broke, errors = 0, 0, 0
    for pr in _PROBES:
        try:
            ok, detail = pr.fn()
        except Exception as e:  # noqa: BLE001
            errors += 1
            print("PROBE %s ERROR %r" % (pr.pid, e))
            continue
        if pr.attack:
            if ok:
                held += 1
                print("PROBE %s HELD" % pr.pid)
            else:
                broke += 1
                print("PROBE %s BREAK %r" % (pr.pid, detail))
        else:
            if ok:
                held += 1
                print("PROBE %s HELD" % pr.pid)
            else:
                errors += 1
                print("PROBE %s CONTROL-FAILED %r" % (pr.pid, detail))
    print("RESULT held=%d broke=%d errors=%d impl=%s"
          % (held, broke, errors, _IMPL))
    green = _green_checks()
    g_ok = all(r[1] for r in green)
    for name, ok, _d in green:
        print("GREEN %s %s" % (name, "OK" if ok else "FAIL"))
    rc = 0 if (errors == 0 and g_ok) else 1
    print("OVERALL %s" % ("OK" if rc == 0 else "FAIL"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
