#!/usr/bin/env python3
"""Wave-271 red-first battery: per-tool grant v2 enforcement refinement.

7 falsifiable properties (12 attack probes + 6 controls), from the
wave-270 prospectus build-ready recommendation (SpiceDB e4b276d7 /
OpenFGA 97943bf6, Apache-2.0; pattern/ceremony only, nothing copied):

  P1 stale mandate_version -> deny (zedtoken discipline)
  P2 predicate-registry content-hash mismatch -> deny
  P3 missing required arg_bounds attribute -> deny + missing fields logged
  P4 request-scoped grant material never persists
  P5 mandate store unreachable -> deny (fail closed, never noop-allow)
  P6 batch verdicts: one per tool call, pinned snapshot, never shared
  P7 admin/data-plane credential separation

Red phase: PTGRANTV2_IMPL=stub -> permissive foil. Every attack probe
must BREAK (the foil allows when it should refuse); a probe that HELDs
on the stub is vacuous and is flagged.
Green phase: default -> gov.tool_grant v2. Every probe must HELD.

Conventions: module-level staging default; verify standalone under
`env -u GOV_DEPLOYMENT_MODE`; depth-1 green checks honoring
GOV_SKIP_GREEN=1; fresh unique /var/tmp TMPDIRs; NO in-repo git
subprocesses.
"""

import json
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import tool_grant as tg  # noqa: E402
from gov import ed25519  # noqa: E402

# Wave-271 ptgrantv2 lane: pin -> 1411 (+6 codes:
# ptgrant-arg-attribute-missing, ptgrant-batch-tool-cap-exceeded,
# ptgrant-caller-unauthorized, ptgrant-context-oversize,
# ptgrant-mandate-unreachable, ptgrant-predicate-hash-mismatch).
# Asserted lane-locally; the merge coordinator repoints at merge.
TAXONOMY_PIN = 1753  # Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)

NEW_CODES = [
    "ptgrant-arg-attribute-missing",
    "ptgrant-batch-tool-cap-exceeded",
    "ptgrant-caller-unauthorized",
    "ptgrant-context-oversize",
    "ptgrant-mandate-unreachable",
    "ptgrant-predicate-hash-mismatch",
]

NOW = 1791000000
SERVER_NAME = "srv"
SERVER_URI = "https://mcp.example/"
TOOL_A, TOOL_B = "tool_a", "tool_b"
MANDATE_ID = "mandate-1"
LINK_A = "sha256:" + "aa" * 32
LINK_B = "sha256:" + "bb" * 32
ISSUER_SEED = b"\x11" * 32
HOLDER_SEED = b"\x22" * 32


# ---------------------------------------------------------------------------
# Permissive stub foil (red phase): allows everything, caches allows
# WITHOUT mandate-version pinning (the naive-cache trap).
# ---------------------------------------------------------------------------

class _StubV2(object):
    """Foil with the v2 gateway call shape but no checks: no caller scope,
    no registry pin, no mandate reachability, no context caps, no batch
    cap, no per-item evaluation. Caches allows keyed WITHOUT the mandate
    version, so a stale allow is served after a mandate bump."""

    def __init__(self):
        self._allow_cache = {}

    def evaluate_request(self, grant, **kw):
        key = (id(grant), kw.get("server_name"), kw.get("tool"))
        cache = kw.get("verdict_cache")
        if cache is not None and key in self._allow_cache:
            return dict(self._allow_cache[key])
        v = {"ok": True, "code": "ptgrant-ok", "detail": "stub allows",
             "checked": ["stub:allow"], "grant_jti": "stub", "remaining": 99}
        self._allow_cache[key] = v
        return dict(v)

    def evaluate_batch(self, items, **kw):
        grant = kw.get("grant")
        rest = {k: v for k, v in kw.items() if k != "grant"}
        return {"snapshot": None,
                "verdicts": [self.evaluate_request(
                    grant, tool=it.get("tool"), args=it.get("args"),
                    proof=it.get("proof"),
                    request_context=it.get("request_context"),
                    caller_cred=rest.get("caller_cred"),
                    verdict_cache=rest.get("verdict_cache"))
                    for it in items]}


def _get_impl():
    """(mode, evaluate_request, evaluate_batch, tg_or_None)."""
    if os.environ.get("PTGRANTV2_IMPL") == "stub":
        stub = _StubV2()
        return "stub", stub.evaluate_request, stub.evaluate_batch, None
    return ("real", tg.evaluate_request, tg.evaluate_batch, tg)


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------

def _fixture():
    mandates = {MANDATE_ID: {"version": 1}}
    issuer = tg.Issuer("sasanam-tool-as", ISSUER_SEED,
                       lambda mid: mandates.get(mid))
    holder_pub = ed25519.publickey(HOLDER_SEED)
    details = [
        {"type": tg.GRANT_TYPE, "identifier": "srv::tool_a",
         "locations": [SERVER_URI], "actions": ["call"],
         "arg_bounds": {"path": {"predicate": "prefix",
                                 "params": {"prefix": "/safe/"}}},
         "supply_chain": {"link_digest": LINK_A}, "max_calls": 5},
        {"type": tg.GRANT_TYPE, "identifier": "srv::tool_b",
         "locations": [SERVER_URI], "actions": ["call"],
         "arg_bounds": {"n": {"predicate": "max_value",
                              "params": {"max_value": 10}}},
         "supply_chain": {"link_digest": LINK_B}, "max_calls": 5},
    ]
    grant = issuer.issue(
        sub="spiffe://example/workload-1", aud=SERVER_URI,
        proof_pub=holder_pub, mandate_id=MANDATE_ID, mandate_version=1,
        details=details, lifetime_s=600, now=NOW)
    links = {"tool_a": LINK_A, "tool_b": LINK_B}

    def base_kw(store):
        return dict(issuer_pub=issuer.issuer_pub, server_name=SERVER_NAME,
                    server_uri=SERVER_URI, now=NOW, usage_store=store,
                    mandate_version_provider=lambda mid: mandates[mid]["version"],
                    link_verifier=lambda tool: links[tool])

    def proof(nonce=None):
        return tg.make_pop_proof(HOLDER_SEED, grant, method="tools/call",
                                 uri=SERVER_URI, now=NOW, nonce=nonce)

    return {"mandates": mandates, "grant": grant, "proof": proof,
            "base_kw": base_kw,
            "cred_dp": {"scopes": ["data-plane"]},
            "cred_admin": {"scopes": ["admin"]},
            "cred_both": {"scopes": ["data-plane", "auditor"]}}


# ---------------------------------------------------------------------------
# Attack probes (must BREAK on the stub, must HELD on the real impl)
# ---------------------------------------------------------------------------

def a01_stale_mandate_version(mode, ev_req, ev_batch, tgmod):
    """P1: mandate bumped after issuance -> stale grant must deny."""
    f = _fixture()
    f["mandates"][MANDATE_ID]["version"] = 2  # kill the mandate
    v = ev_req(f["grant"], proof=f["proof"]("n-a01"), tool="tool_a",
               args={"path": "/safe/x"}, request_context=None,
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if v["ok"] else "HELD",
                "foil allowed stale-mandate grant" if v["ok"]
                else "foil refused (vacuous probe)")
    good = (not v["ok"]) and v["code"] == "ptgrant-mandate-drift"
    return ("HELD" if good else "BREAK",
            "code=%s (want ptgrant-mandate-drift)" % (v.get("code"),))


def a02_predicate_hash_mismatch(mode, ev_req, ev_batch, tgmod):
    """P2: registry content drift vs the pinned hash -> deny."""
    f = _fixture()
    if mode == "stub":
        v = ev_req(f["grant"], proof=f["proof"]("n-a02"), tool="tool_a",
                   args={"path": "/safe/x"}, request_context=None,
                   caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
        return ("BREAK" if v["ok"] else "HELD",
                "foil allowed hash-drifted registry" if v["ok"]
                else "foil refused (vacuous probe)")
    tgmod.PREDICATE_REGISTRY["__w271_evil__"] = lambda a, p: True
    try:
        v = ev_req(f["grant"], proof=f["proof"]("n-a02"), tool="tool_a",
                   args={"path": "/safe/x"}, request_context=None,
                   caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    finally:
        del tgmod.PREDICATE_REGISTRY["__w271_evil__"]
    good = (not v["ok"]) and v["code"] == "ptgrant-predicate-hash-mismatch"
    return ("HELD" if good else "BREAK",
            "code=%s (want ptgrant-predicate-hash-mismatch)" % (v.get("code"),))


def a03_missing_arg_attribute(mode, ev_req, ev_batch, tgmod):
    """P3: required arg_bounds attribute absent -> deny + fields logged."""
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-a03"), tool="tool_a",
               args={}, request_context=None,
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if v["ok"] else "HELD",
                "foil allowed missing-attribute call" if v["ok"]
                else "foil refused (vacuous probe)")
    good = ((not v["ok"]) and v["code"] == "ptgrant-arg-attribute-missing"
            and "path" in v.get("detail", ""))
    return ("HELD" if good else "BREAK",
            "code=%s detail=%r" % (v.get("code"), v.get("detail")))


def a04_request_context_not_persisted(mode, ev_req, ev_batch, tgmod):
    """P4: request-scoped material must not persist across calls."""
    f = _fixture()
    kw1 = f["base_kw"](tg.UsageStore())
    v1 = ev_req(f["grant"], proof=f["proof"]("n-a04a"), tool="tool_a",
                args={}, request_context={"path": "/safe/x"},
                caller_cred=f["cred_dp"], **kw1)
    v2 = ev_req(f["grant"], proof=f["proof"]("n-a04b"), tool="tool_a",
                args={}, request_context=None,
                caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if (v1["ok"] and v2["ok"]) else "HELD",
                "foil allowed the context-less second call")
    residue = b"request_context" in json.dumps(
        f["grant"], sort_keys=True).encode()
    good = (v1["ok"] and (not v2["ok"])
            and v2["code"] == "ptgrant-arg-attribute-missing"
            and not residue)
    return ("HELD" if good else "BREAK",
            "v1=%s v2=%s residue=%s" % (v1["ok"], v2.get("code"), residue))


def a05_backend_unreachable(mode, ev_req, ev_batch, tgmod):
    """P5: mandate store unreachable -> deny (fail closed, never allow)."""
    f = _fixture()

    def boom(_mid):
        raise ConnectionError("store down")

    kw = f["base_kw"](tg.UsageStore())
    kw["mandate_version_provider"] = boom
    v = ev_req(f["grant"], proof=f["proof"]("n-a05"), tool="tool_a",
               args={"path": "/safe/x"}, request_context=None,
               caller_cred=f["cred_dp"], **kw)
    kw2 = f["base_kw"](tg.UsageStore())
    kw2["mandate_version_provider"] = lambda _mid: None
    v2 = ev_req(f["grant"], proof=f["proof"]("n-a05b"), tool="tool_a",
                args={"path": "/safe/x"}, request_context=None,
                caller_cred=f["cred_dp"], **kw2)
    if mode == "stub":
        return ("BREAK" if (v["ok"] and v2["ok"]) else "HELD",
                "foil allowed unreachable-backend call")
    good = ((not v["ok"]) and v["code"] == "ptgrant-mandate-unreachable"
            and (not v2["ok"]) and v2["code"] == "ptgrant-mandate-unreachable")
    return ("HELD" if good else "BREAK",
            "raise->%s none->%s" % (v.get("code"), v2.get("code")))


def a06_batch_partial_coverage(mode, ev_req, ev_batch, tgmod):
    """P6: batch of 3, grant covers 2 -> exactly the uncovered denied."""
    f = _fixture()
    items = [
        {"tool": "tool_a", "args": {"path": "/safe/x"},
         "proof": f["proof"]("n-a06a"), "request_context": None},
        {"tool": "tool_b", "args": {"n": 3},
         "proof": f["proof"]("n-a06b"), "request_context": None},
        {"tool": "tool_c", "args": {},
         "proof": f["proof"]("n-a06c"), "request_context": None},
    ]
    r = ev_batch(items, grant=f["grant"], caller_cred=f["cred_dp"],
                 **f["base_kw"](tg.UsageStore()))
    vs = r["verdicts"]
    if mode == "stub":
        return ("BREAK" if all(v["ok"] for v in vs) else "HELD",
                "foil allowed the uncovered tool_c")
    good = (vs[0]["ok"] and vs[1]["ok"] and (not vs[2]["ok"])
            and vs[2]["code"] == "ptgrant-tool-not-covered")
    return ("HELD" if good else "BREAK",
            "codes=%s" % ([v.get("code") for v in vs],))


def a07_admin_credential_on_dataplane(mode, ev_req, ev_batch, tgmod):
    """P7: admin-scoped credential cannot satisfy a data-plane check."""
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-a07"), tool="tool_a",
               args={"path": "/safe/x"}, request_context=None,
               caller_cred=f["cred_admin"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if v["ok"] else "HELD",
                "foil allowed admin credential on data plane")
    good = (not v["ok"]) and v["code"] == "ptgrant-caller-unauthorized"
    return ("HELD" if good else "BREAK",
            "code=%s (want ptgrant-caller-unauthorized)" % (v.get("code"),))


def a08_batch_tool_cap(mode, ev_req, ev_batch, tgmod):
    """Batch cap: 3 items with max_tools_per_request=2 -> all denied."""
    f = _fixture()
    items = [
        {"tool": "tool_a", "args": {"path": "/safe/x"},
         "proof": f["proof"]("n-a08a"), "request_context": None},
        {"tool": "tool_b", "args": {"n": 3},
         "proof": f["proof"]("n-a08b"), "request_context": None},
        {"tool": "tool_a", "args": {"path": "/safe/y"},
         "proof": f["proof"]("n-a08c"), "request_context": None},
    ]
    r = ev_batch(items, grant=f["grant"], caller_cred=f["cred_dp"],
                 max_tools_per_request=2, **f["base_kw"](tg.UsageStore()))
    vs = r["verdicts"]
    if mode == "stub":
        return ("BREAK" if all(v["ok"] for v in vs) else "HELD",
                "foil ignored the per-request tool cap")
    good = (len(vs) == 3 and all((not v["ok"])
            and v["code"] == "ptgrant-batch-tool-cap-exceeded" for v in vs))
    return ("HELD" if good else "BREAK",
            "codes=%s" % ([v.get("code") for v in vs],))


def a09_context_oversize(mode, ev_req, ev_batch, tgmod):
    """Caller-supplied context is size-capped as untrusted input."""
    f = _fixture()
    ctx = {"path": "/safe/x", "pad": "y" * 8000}
    v = ev_req(f["grant"], proof=f["proof"]("n-a09"), tool="tool_a",
               args={}, request_context=ctx,
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if v["ok"] else "HELD",
                "foil allowed oversized context")
    good = (not v["ok"]) and v["code"] == "ptgrant-context-oversize"
    return ("HELD" if good else "BREAK",
            "code=%s (want ptgrant-context-oversize)" % (v.get("code"),))


def a10_stale_verdict_cache(mode, ev_req, ev_batch, tgmod):
    """Cached verdicts must key on mandate_version: no stale allow."""
    f = _fixture()
    cache = {}
    v1 = ev_req(f["grant"], proof=f["proof"]("n-a10a"), tool="tool_a",
                args={"path": "/safe/x"}, request_context=None,
                caller_cred=f["cred_dp"], verdict_cache=cache,
                **f["base_kw"](tg.UsageStore()))
    f["mandates"][MANDATE_ID]["version"] = 2  # revoke between calls
    v2 = ev_req(f["grant"], proof=f["proof"]("n-a10b"), tool="tool_a",
                args={"path": "/safe/x"}, request_context=None,
                caller_cred=f["cred_dp"], verdict_cache=cache,
                **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if (v1["ok"] and v2["ok"]) else "HELD",
                "foil served a stale cached allow after the mandate bump")
    good = (v1["ok"] and (not v2["ok"])
            and v2["code"] == "ptgrant-mandate-drift")
    return ("HELD" if good else "BREAK",
            "v1=%s v2=%s (want allow then ptgrant-mandate-drift)"
            % (v1["ok"], v2.get("code")))


def a11_context_type_confusion(mode, ev_req, ev_batch, tgmod):
    """Per-call context is attacker-influenced: type-checked, never trusted."""
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-a11"), tool="tool_a",
               args={}, request_context={"path": 12345},
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if v["ok"] else "HELD",
                "foil allowed type-confused context")
    good = (not v["ok"]) and v["code"] == "ptgrant-arg-bound-violated"
    return ("HELD" if good else "BREAK",
            "code=%s (want ptgrant-arg-bound-violated)" % (v.get("code"),))


def a12_no_conditional_state(mode, ev_req, ev_batch, tgmod):
    """No third permission state reaches the executor: hard deny + reason."""
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-a12"), tool="tool_a",
               args={}, request_context=None,
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    if mode == "stub":
        return ("BREAK" if v["ok"] else "HELD",
                "foil authorized an unevaluable call")
    good = (v["ok"] is False and isinstance(v.get("code"), str)
            and isinstance(v.get("detail"), str) and bool(v["detail"]))
    return ("HELD" if good else "BREAK",
            "ok=%r code=%r" % (v["ok"], v.get("code")))


# ---------------------------------------------------------------------------
# Controls (must HELD in both phases)
# ---------------------------------------------------------------------------

def c1_valid_single_request(mode, ev_req, ev_batch, tgmod):
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-c1"), tool="tool_a",
               args={"path": "/safe/x"}, request_context=None,
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    return ("HELD" if v["ok"] else "BREAK", "code=%s" % (v.get("code"),))


def c2_batch_all_covered(mode, ev_req, ev_batch, tgmod):
    f = _fixture()
    items = [
        {"tool": "tool_a", "args": {"path": "/safe/x"},
         "proof": f["proof"]("n-c2a"), "request_context": None},
        {"tool": "tool_b", "args": {"n": 3},
         "proof": f["proof"]("n-c2b"), "request_context": None},
    ]
    r = ev_batch(items, grant=f["grant"], caller_cred=f["cred_dp"],
                 **f["base_kw"](tg.UsageStore()))
    good = all(v["ok"] for v in r["verdicts"])
    return ("HELD" if good else "BREAK",
            "codes=%s" % ([v.get("code") for v in r["verdicts"]],))


def c3_context_provides_attribute(mode, ev_req, ev_batch, tgmod):
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-c3"), tool="tool_a",
               args={}, request_context={"path": "/safe/x"},
               caller_cred=f["cred_dp"], **f["base_kw"](tg.UsageStore()))
    return ("HELD" if v["ok"] else "BREAK", "code=%s" % (v.get("code"),))


def c4_extra_scopes_still_data_plane(mode, ev_req, ev_batch, tgmod):
    f = _fixture()
    v = ev_req(f["grant"], proof=f["proof"]("n-c4"), tool="tool_b",
               args={"n": 3}, request_context=None,
               caller_cred=f["cred_both"], **f["base_kw"](tg.UsageStore()))
    return ("HELD" if v["ok"] else "BREAK", "code=%s" % (v.get("code"),))


def c5_deterministic(mode, ev_req, ev_batch, tgmod):
    f = _fixture()
    kw = lambda store, nonce: dict(  # noqa: E731
        proof=f["proof"](nonce), tool="tool_a", args={"path": "/safe/x"},
        request_context=None, caller_cred=f["cred_dp"],
        **f["base_kw"](store))
    v1 = ev_req(f["grant"], **kw(tg.UsageStore(), "n-c5a"))
    v2 = ev_req(f["grant"], **kw(tg.UsageStore(), "n-c5b"))
    good = (v1["ok"], v1["code"]) == (v2["ok"], v2["code"])
    return ("HELD" if good else "BREAK",
            "run1=(%s,%s) run2=(%s,%s)"
            % (v1["ok"], v1.get("code"), v2["ok"], v2.get("code")))


def c6_taxonomy_pin(mode, ev_req, ev_batch, tgmod):
    # The pin is a taxonomy property, independent of the evaluation mode:
    # assert it in both phases. (The pre-implementation red run additionally
    # recorded feature-absence of the v2 surface; that evidence lives in
    # the lane REPORT.md.)
    from gov import decision_codes as dc  # noqa: F401
    import re
    src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
    lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
    hits = [c for c in NEW_CODES if lits.count(c) == 1]
    good = (len(lits) == TAXONOMY_PIN and len(set(lits)) == len(lits)
            and len(hits) == len(NEW_CODES))
    return ("HELD" if good else "BREAK",
            "literals=%d unique=%d new-once=%d/%d"
            % (len(lits), len(set(lits)), len(hits), len(NEW_CODES)))


ATTACKS = [a01_stale_mandate_version, a02_predicate_hash_mismatch,
           a03_missing_arg_attribute, a04_request_context_not_persisted,
           a05_backend_unreachable, a06_batch_partial_coverage,
           a07_admin_credential_on_dataplane, a08_batch_tool_cap,
           a09_context_oversize, a10_stale_verdict_cache,
           a11_context_type_confusion, a12_no_conditional_state]
CONTROLS = [c1_valid_single_request, c2_batch_all_covered,
            c3_context_provides_attribute, c4_extra_scopes_still_data_plane,
            c5_deterministic, c6_taxonomy_pin]


# ---------------------------------------------------------------------------
# Depth-1 green check
# ---------------------------------------------------------------------------

def _green_check():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        return "SKIP (GOV_SKIP_GREEN=1)"
    tmp = tempfile.mkdtemp(prefix="g271v2-green-", dir="/var/tmp")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        r = subprocess.run(
            [sys.executable, os.path.join(_HERE, "w270_ptgrant_probes.py")],
            env=env, capture_output=True, text=True, timeout=600,
            cwd=_REPO)
    except Exception as exc:  # noqa: BLE001
        return "FAIL: %r" % (exc,)
    if r.returncode != 0:
        return "FAIL rc=%d: %s" % (r.returncode, r.stderr[-400:])
    return "OK"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    mode, ev_req, ev_batch, tgmod = _get_impl()
    rows = []
    counts = {"HELD": 0, "BREAK": 0, "ERROR": 0}
    for fn in ATTACKS + CONTROLS:
        kind = "attack" if fn in ATTACKS else "control"
        try:
            outcome, note = fn(mode, ev_req, ev_batch, tgmod)
        except Exception as exc:  # noqa: BLE001
            outcome, note = "ERROR", "%r" % (exc,)
        if outcome not in counts:
            outcome = "ERROR"
        counts[outcome] += 1
        rows.append((fn.__name__, kind, outcome, note))
    green = _green_check()
    print("mode=%s" % (mode,))
    for name, kind, outcome, note in rows:
        print("%-38s %-7s %-5s %s" % (name, kind, outcome, note))
    print("ATTACKS: %d/%d BREAK (want %d/%d on stub, 0 on real)"
          % (sum(1 for n, k, o, _ in rows if k == "attack" and o == "BREAK"),
             len(ATTACKS), len(ATTACKS) if mode == "stub" else 0,
             len(ATTACKS)))
    print("RESULT %d HELD / %d BREAK / %d ERROR; green=%s"
          % (counts["HELD"], counts["BREAK"], counts["ERROR"], green))
    if mode == "stub":
        bad = [n for n, k, o, _ in rows if k == "attack" and o != "BREAK"]
        bad += [n for n, k, o, _ in rows if k == "control" and o != "HELD"]
    else:
        bad = [n for n, k, o, _ in rows if o != "HELD"]
    if green not in ("OK",) and not green.startswith("SKIP"):
        bad.append("green-check")
    if bad:
        print("FAIL: %s" % (", ".join(bad),))
        return 1
    print("GREEN=1/1" if green == "OK" else "GREEN skipped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
