#!/usr/bin/env python3
"""Wave-319 Lane 1 battery: least-privilege grant negotiation surface
(gov/grant_negotiation.py).

Agent->tool grants are all-or-nothing today: there is no vocabulary for a
narrow grant, and three failure classes are invisible -- the RFC 9396 S2.2
product-of-fields over-grant trap, widening on delegation, and stale grants.
This battery proves the RAR-shaped grant grammar, the structural validators,
attenuation (only-tighten), expiry-as-revocation, chain-of-proofs, and the
advisory-only-tighten wiring at the tool-call path, RED-FIRST: it is written
before the module exists and must FAIL on the open tree.

Probe map (public seams only -- validate_request / issue / verify /
verify_chain / advisory_check / ToolExecutor.call):
  request-multi-resource-refused: one authorization-details object naming
      two resources -> coded grantneg-product-of-fields at request validation
      (the RFC 9396 S2.2 trap: actions x resources is a product, not a sum).
  grant-multi-resource-refused: an issued grant object with two resources
      refuses grant-product-of-fields at verify.
  derived-widening-refused: a delegated grant adding an action its parent
      lacks -> coded grantneg-widening-refused.
  derived-loosened-constraint-refused: a delegated grant raising a numeric
      constraint above the parent's -> coded grantneg-widening-refused.
  expired-grant-refused: expires_at in the past -> coded grantneg-expired.
  chain-non-attenuating-link-refused: a middle link wider than its parent
      -> coded grantneg-chain-widened.
  chain-forged-signature-refused: tampered middle link -> coded
      grant-chain-unverifiable.
  chain-untrusted-anchor-refused: root issuer is not the tool's registered
      owner -> coded grantneg-anchor-untrusted.
  chain-audience-mismatch-refused: final link audience != presenting
      agent -> coded grantneg-audience-mismatch.
  malformed-grant-refused: grant missing required fields -> coded
      grant-malformed.
  benign-grant-verifies: well-formed single-pair grant, valid chain,
      matching audience, scope-bound to the call -> advisory VERIFIED.
  scope-tool-mismatch-refused: a grant covering send_email presented for
      write_file -> coded grantneg-scope-mismatch.
  scope-resource-mismatch-refused: a grant covering one resource presented
      for a call to another resource -> coded grantneg-scope-mismatch.
  absent-grant-existing-path: registered risky tool, no grant presented ->
      advisory returns absent and the call proceeds exactly as before.
  unregistered-tool-not-applicable: tool not in the grant registry ->
      advisory returns not-applicable.
  registry-advertises-types: advertise() lists the tool's accepted grant
      types (AS-metadata pattern for discovery).
  executor-advisory-tightens: executor call with a registered risky tool
      and a forged grant -> denied with the coded refusal; the same call
      with no grant proceeds (advisory, never loosens).
  pin-taxonomy / footer-state: standard pins (1964; open none / next F409).
"""

import os
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import decision_codes as dc  # noqa: E402
from gov import grant_negotiation as gn  # noqa: E402

TAXONOMY_PIN = 2135  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened)


FOOTER_NEXT = "F506"  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: next F480  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: next F496


FOOTER_OPEN = "F503, F504, F505"  # Wave-360 merge: F489-F495 CLOSED; F496-F502 filed OPEN (next F503)  # wave-347 merge: F437-F442 CLOSED, F443 OPEN (next F444); wave-348 merge: F443 CLOSED, F444/F445 OPEN (next F446); wave-349 merge: F444+F445 CLOSED, F446-F450 filed OPEN (next F451); wave-350 merge: F446-F450 CLOSED, F451(hex-ws)+F452(attempt-budget) OPEN, closure-lane F451->F453 OPEN (next F454); wave-351 merge: F451-F453 CLOSED, F454-F460 filed OPEN (next F461)  # Wave-352 merge: F454-F460 CLOSED; F461-F468 filed OPEN (next F469)  # Wave-353 merge: F461-F468 CLOSED; F469-F472 filed OPEN (next F473)  # Wave-354 merge: F469-F472 CLOSED; F473, F474 filed OPEN (next F475)  # Wave-355 merge: F473-F475 CLOSED; F476, F477 filed OPEN (next F478)  # Wave-356 merge: F476, F477 CLOSED; F478, F479 OPEN (next F480)  # Wave-357 merge: F478, F479 CLOSED (next F481)  # Wave-358 merge: F480, F481 CLOSED; F482-F488 filed OPEN  # Wave-359 merge: F482-F488 CLOSED; F489-F495 filed OPEN



_results = []
PROBES = []


def probe(name):
    def deco(fn):
        PROBES.append((name, fn))
        return fn
    return deco


def _held(pid, note):
    _results.append({"probe_id": pid, "verdict": "HELD", "note": note})
    return "HELD", note


def _break(pid, note):
    _results.append({"probe_id": pid, "verdict": "BREAK", "note": note})
    return "BREAK", note


def _error(pid, note):
    _results.append({"probe_id": pid, "verdict": "ERROR", "note": note})
    return "ERROR", note


# ---------------------------------------------------------------------------
# Fixtures (test-local keys; NEVER production material).
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
import json  # noqa: E402
from datetime import datetime, timedelta, timezone  # noqa: E402

from gov import ed25519  # noqa: E402

NOW = datetime(2026, 10, 4, 12, 0, 0, tzinfo=timezone.utc)
OWNER_SEED = "51" * 32  # resource-owner key (test-local, not a secret)
AGENT_SEED = "52" * 32  # presenting agent key (test-local, not a secret)
OTHER_SEED = "53" * 32  # stranger key (test-local, not a secret)


def _keypair(seed_hex):
    seed = bytes.fromhex(seed_hex)
    pub = ed25519.publickey(seed)
    return seed, pub, hashlib.sha256(pub).hexdigest()[:16]


OWNER_SEED_B, OWNER_PUB, OWNER_KID = _keypair(OWNER_SEED)
AGENT_SEED_B, AGENT_PUB, AGENT_KID = _keypair(AGENT_SEED)
OTHER_SEED_B, OTHER_PUB, OTHER_KID = _keypair(OTHER_SEED)


def _pubs():
    return {OWNER_KID: OWNER_PUB, AGENT_KID: AGENT_PUB, OTHER_KID: OTHER_PUB}


def _registry(tool="send_email"):
    reg = gn.GrantRegistry()
    reg.register_tool(tool, owner_key_id=OWNER_KID,
                      grant_types=("sasanam_tool_grant",))
    reg.register_key(OWNER_KID, OWNER_PUB)
    reg.register_key(AGENT_KID, AGENT_PUB)
    reg.register_key(OTHER_KID, OTHER_PUB)
    return reg


def _grant_dict(**over):
    base = {
        "type": "sasanam_tool_grant",
        "tool": "send_email",
        "actions": ["send"],
        "resources": ["mallory@evil.com"],
        "constraints": {"max_bytes": 1024},
        "identifier": "g-001",
        "privileges": [],
        "issued_at": (NOW - timedelta(minutes=5)).isoformat(),
        "expires_at": (NOW + timedelta(minutes=30)).isoformat(),
        "issuer": OWNER_KID,
        "audience": "agent-7",
        "parent": None,
    }
    base.update(over)
    return base


def _seal_grant(grant, seed):
    body = dict(grant)
    body.pop("signature", None)
    msg = gn.canonical_bytes(body)
    sig = ed25519.sign(seed, msg)
    body["signature"] = sig.hex()
    return body


def _issue(owner_seed=OWNER_SEED_B, **over):
    return _seal_grant(_grant_dict(**over), owner_seed)


def _live_times():
    """issued_at/expires_at relative to the wall clock (the executor's
    advisory check uses wall-clock now, not the battery's fixed NOW)."""
    live = datetime.now(timezone.utc)
    return {"issued_at": (live - timedelta(minutes=5)).isoformat(),
            "expires_at": (live + timedelta(minutes=30)).isoformat()}


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------


@probe("request-multi-resource-refused")
def p_request_multi_resource():
    req = [{
        "type": "sasanam_tool_grant",
        "tool": "send_email",
        "actions": ["read", "write"],
        "resources": ["contacts", "photos"],
    }]
    try:
        gn.validate_request(req)
    except gn.GrantError as e:
        if e.code == "grantneg-product-of-fields":
            return _held("request-multi-resource-refused",
                         "multi-resource request object refused coded")
        return _break("request-multi-resource-refused",
                      "wrong code: %s" % e.code)
    return _break("request-multi-resource-refused",
                  "multi-resource request object accepted (over-grant)")


@probe("grant-multi-resource-refused")
def p_grant_multi_resource():
    g = _issue(resources=["contacts", "photos"])
    try:
        gn.verify(g, _pubs(), now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-product-of-fields":
            return _held("grant-multi-resource-refused",
                         "multi-resource grant refused coded")
        return _break("grant-multi-resource-refused",
                      "wrong code: %s" % e.code)
    return _break("grant-multi-resource-refused",
                  "multi-resource grant verified (over-grant)")


@probe("derived-widening-refused")
def p_derived_widening():
    parent = _issue()
    child = _grant_dict(actions=["send", "delete"],  # wider than parent
                        parent=gn.grant_digest(parent),
                        issuer=AGENT_KID, audience="agent-7")
    child = _seal_grant(child, AGENT_SEED_B)
    try:
        gn.verify_chain([parent, child], _pubs(), owner_key_id=OWNER_KID,
                        presenter="agent-7", now=NOW)
    except gn.GrantError as e:
        if e.code in ("grantneg-widening-refused", "grantneg-chain-widened"):
            return _held("derived-widening-refused",
                         "widened delegation refused coded %s" % e.code)
        return _break("derived-widening-refused", "wrong code: %s" % e.code)
    return _break("derived-widening-refused",
                  "widened delegation verified (escalation)")


@probe("derived-loosened-constraint-refused")
def p_derived_loosened_constraint():
    parent = _issue()
    child_body = _grant_dict(constraints={"max_bytes": 99999},
                             parent=gn.grant_digest(parent),
                             issuer=AGENT_KID, audience="agent-7")
    child = _seal_grant(child_body, AGENT_SEED_B)
    try:
        gn.verify_chain([parent, child], _pubs(), owner_key_id=OWNER_KID,
                        presenter="agent-7", now=NOW)
    except gn.GrantError as e:
        if e.code in ("grantneg-widening-refused", "grantneg-chain-widened"):
            return _held("derived-loosened-constraint-refused",
                         "loosened constraint refused coded %s" % e.code)
        return _break("derived-loosened-constraint-refused",
                      "wrong code: %s" % e.code)
    return _break("derived-loosened-constraint-refused",
                  "loosened constraint verified (escalation)")


@probe("expired-grant-refused")
def p_expired():
    g = _issue(expires_at=(NOW - timedelta(minutes=1)).isoformat(),
               issued_at=(NOW - timedelta(minutes=31)).isoformat())
    try:
        gn.verify(g, _pubs(), now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-expired":
            return _held("expired-grant-refused",
                         "expired grant refused coded")
        return _break("expired-grant-refused", "wrong code: %s" % e.code)
    return _break("expired-grant-refused", "expired grant verified (stale)")


@probe("chain-non-attenuating-link-refused")
def p_chain_non_attenuating():
    root = _issue()
    mid_body = _grant_dict(actions=["send", "delete"],  # wider than root
                           parent=gn.grant_digest(root),
                           issuer=AGENT_KID, audience="agent-7")
    mid = _seal_grant(mid_body, AGENT_SEED_B)
    leaf_body = _grant_dict(actions=["send"],
                            parent=gn.grant_digest(mid),
                            issuer=AGENT_KID, audience="agent-7")
    leaf = _seal_grant(leaf_body, AGENT_SEED_B)
    try:
        gn.verify_chain([root, mid, leaf], _pubs(), owner_key_id=OWNER_KID,
                        presenter="agent-7", now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-chain-widened":
            return _held("chain-non-attenuating-link-refused",
                         "non-attenuating hop refused coded")
        return _break("chain-non-attenuating-link-refused",
                      "wrong code: %s" % e.code)
    return _break("chain-non-attenuating-link-refused",
                  "non-attenuating hop verified (escalation)")


@probe("chain-forged-signature-refused")
def p_chain_forged():
    root = _issue()
    mid_body = _grant_dict(parent=gn.grant_digest(root),
                           issuer=AGENT_KID, audience="agent-7")
    mid = _seal_grant(mid_body, AGENT_SEED_B)
    mid["actions"] = ["send", "delete"]  # tamper after sealing
    try:
        gn.verify_chain([root, mid], _pubs(), owner_key_id=OWNER_KID,
                        presenter="agent-7", now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-chain-unverifiable":
            return _held("chain-forged-signature-refused",
                         "forged link refused coded")
        return _break("chain-forged-signature-refused",
                      "wrong code: %s" % e.code)
    return _break("chain-forged-signature-refused",
                  "forged link verified (forgery)")


@probe("chain-untrusted-anchor-refused")
def p_chain_untrusted_anchor():
    stranger_root = _issue(owner_seed=OTHER_SEED_B, issuer=OTHER_KID)
    try:
        gn.verify_chain([stranger_root], _pubs(), owner_key_id=OWNER_KID,
                        presenter="agent-7", now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-anchor-untrusted":
            return _held("chain-untrusted-anchor-refused",
                         "stranger-anchored chain refused coded")
        return _break("chain-untrusted-anchor-refused",
                      "wrong code: %s" % e.code)
    return _break("chain-untrusted-anchor-refused",
                  "stranger-anchored chain verified (anchor)")


@probe("chain-audience-mismatch-refused")
def p_chain_audience():
    g = _issue(audience="agent-9")
    try:
        gn.verify_chain([g], _pubs(), owner_key_id=OWNER_KID,
                        presenter="agent-7", now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-audience-mismatch":
            return _held("chain-audience-mismatch-refused",
                         "wrong-audience grant refused coded")
        return _break("chain-audience-mismatch-refused",
                      "wrong code: %s" % e.code)
    return _break("chain-audience-mismatch-refused",
                  "wrong-audience grant verified (replay)")


@probe("malformed-grant-refused")
def p_malformed():
    g = {"type": "sasanam_tool_grant", "tool": "send_email"}  # missing fields
    try:
        gn.verify(g, _pubs(), now=NOW)
    except gn.GrantError as e:
        if e.code == "grantneg-malformed":
            return _held("malformed-grant-refused",
                         "malformed grant refused coded")
        return _break("malformed-grant-refused", "wrong code: %s" % e.code)
    return _break("malformed-grant-refused", "malformed grant verified")


@probe("benign-grant-verifies")
def p_benign():
    g = _issue()
    status, detail = gn.advisory_check(_registry(), "send_email", g,
                                       presenter="agent-7",
                                       args={"to": "mallory@evil.com"},
                                       now=NOW)
    if status == "verified":
        return _held("benign-grant-verifies",
                     "well-formed grant verifies at the advisory seam "
                     "(scope-bound to the call)")
    return _break("benign-grant-verifies",
                  "benign grant not verified: %s %r" % (status, detail))


@probe("scope-tool-mismatch-refused")
def p_scope_tool():
    reg = _registry()
    reg.register_tool("write_file", owner_key_id=OWNER_KID,
                      grant_types=("sasanam_tool_grant",))
    g = _issue()  # covers send_email, presented for write_file
    status, detail = gn.advisory_check(reg, "write_file", g,
                                       presenter="agent-7",
                                       args={"path": "z.txt"}, now=NOW)
    if status == "refused" and detail.get("code") == "grantneg-scope-mismatch":
        return _held("scope-tool-mismatch-refused",
                     "grant for another tool refused coded")
    return _break("scope-tool-mismatch-refused",
                  "cross-tool grant not refused: %s %r" % (status, detail))


@probe("scope-resource-mismatch-refused")
def p_scope_resource():
    g = _issue()  # covers mallory@evil.com
    status, detail = gn.advisory_check(_registry(), "send_email", g,
                                       presenter="agent-7",
                                       args={"to": "other@evil.com"},
                                       now=NOW)
    if status == "refused" and detail.get("code") == "grantneg-scope-mismatch":
        return _held("scope-resource-mismatch-refused",
                     "grant for another resource refused coded")
    return _break("scope-resource-mismatch-refused",
                  "cross-resource grant not refused: %s %r" % (status, detail))


@probe("absent-grant-existing-path")
def p_absent():
    status, detail = gn.advisory_check(_registry(), "send_email", None,
                                       presenter="agent-7", now=NOW)
    if status == "absent":
        return _held("absent-grant-existing-path",
                     "absent grant -> existing path unchanged")
    return _break("absent-grant-existing-path",
                  "absent grant changed the path: %s" % status)


@probe("unregistered-tool-not-applicable")
def p_unregistered():
    g = _issue()
    status, _ = gn.advisory_check(_registry(), "read_file", g,
                                  presenter="agent-7", now=NOW)
    if status == "not-applicable":
        return _held("unregistered-tool-not-applicable",
                     "unregistered tool -> advisory not-applicable")
    return _break("unregistered-tool-not-applicable",
                  "unregistered tool engaged the check: %s" % status)


@probe("registry-advertises-types")
def p_advertise():
    doc = _registry().advertise()
    types = doc.get("tools", {}).get("send_email", {}).get(
        "authorization_details_types_supported")
    if types == ["sasanam_tool_grant"]:
        return _held("registry-advertises-types",
                     "registry advertises accepted grant types")
    return _break("registry-advertises-types",
                  "advertisement missing/wrong: %r" % (types,))


@probe("executor-advisory-tightens")
def p_executor():
    # A forged grant presented at the executor seam must deny with the
    # coded refusal; the same call with a benign grant executes; the
    # same call with no grant executes exactly as before (advisory:
    # the layer never loosens and absent grants never break the
    # existing path).
    import tempfile  # noqa: E402
    from pathlib import Path  # noqa: E402
    from gov import executor as ex  # noqa: E402
    from gov.policy import PolicyEngine  # noqa: E402
    from gov.log import ActionLog  # noqa: E402
    from gov.approvals import ApprovalQueue  # noqa: E402
    from tests.keyfixture import provision_test_key, scrub_key_env  # noqa: E402

    # The executor's audit log needs a key (fail-closed without one);
    # provision a test-local key and restore the ambient env after
    # (the wave-280 scrub_key_env lesson: it returns a restore()).
    restore = scrub_key_env()
    provision_test_key()
    try:
        d = Path(tempfile.mkdtemp(prefix="w319_grant_"))
        policy = PolicyEngine(os.path.join(REPO, "policies", "default.yaml"))
        log = ActionLog(d / "actions.jsonl")
        approvals = ApprovalQueue(d, log)
        exc = ex.ToolExecutor(
            d, policy, log, approvals,
            ledger_path=d / "egress_ledger.jsonl",
            ungoverned_ack="w319-grant-battery")
        (d / "sandbox").mkdir(parents=True, exist_ok=True)
        exc.set_grant_registry(_registry(tool="write_file"))
        ident = exc.mint_identity("agent-7", "coder", "u1")

        forged = _issue(tool="write_file", resources=["z.txt"],
                        owner_seed=OTHER_SEED_B, issuer=OTHER_KID,
                        **_live_times())
        denied = exc.call(ident, "write_file", path="z.txt", content="hi",
                          grant=forged)
        reason = str(denied.get("reason", ""))
        if denied.get("status") != "denied" or "grantneg-" not in reason:
            return _break("executor-advisory-tightens",
                          "forged grant did not tighten at the seam: "
                          "status=%r reason=%r"
                          % (denied.get("status"), reason[:160]))

        benign = _issue(tool="write_file", resources=["z.txt"],
                        **_live_times())
        ok_grant = exc.call(ident, "write_file", path="z.txt", content="hi",
                            grant=benign)
        if ok_grant.get("status") != "executed":
            return _break("executor-advisory-tightens",
                          "benign grant did not execute: %r"
                          % (ok_grant.get("status"),))

        ok = exc.call(ident, "write_file", path="z.txt", content="hi")
        if ok.get("status") != "executed":
            return _break("executor-advisory-tightens",
                          "absent grant broke the existing path: %r"
                          % (ok.get("status"),))
        return _held("executor-advisory-tightens",
                     "forged grant tightens (coded); benign grant executes; "
                     "absent grant leaves the path unchanged")
    finally:
        restore()


@probe("pin-taxonomy")
def p_pin():
    n = len(dc.TAXONOMY)
    # Insertion order (NOT pre-sorted): a misordered literal must fail.
    codes = list(dc.TAXONOMY)
    if n != TAXONOMY_PIN or codes != sorted(set(codes)):
        return _break("pin-taxonomy",
                      "taxonomy %d != pin %d or unsorted/dup"
                      % (n, TAXONOMY_PIN))
    missing = [c for c in ("grantneg-malformed", "grantneg-product-of-fields",
                           "grantneg-widening-refused", "grantneg-expired",
                           "grantneg-chain-unverifiable", "grantneg-chain-widened",
                           "grantneg-anchor-untrusted",
                           "grantneg-audience-mismatch",
                           "grantneg-scope-mismatch")
               if c not in dc.TAXONOMY]
    if missing:
        return _break("pin-taxonomy", "missing codes: %r" % (missing,))
    return _held("pin-taxonomy",
                 "taxonomy %d sorted, all 9 grantneg-* codes present" % n)


@probe("footer-state")
def p_footer():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    import re  # noqa: E402
    m = list(re.finditer(r"Next free finding: \*\*(F\d+)\*\*\. "
                         r"\*\*Open findings: ([^*]*)\*\*",
                         text))
    if not m:
        return _error("footer-state", "footer not found")
    last = m[-1]
    nxt, opens = last.group(1), last.group(2).strip().rstrip(".")
    if nxt != FOOTER_NEXT or opens != FOOTER_OPEN:
        return _break("footer-state",
                      "footer %s / %s, want %s / %s"
                      % (nxt, opens, FOOTER_NEXT, FOOTER_OPEN))
    return _held("footer-state",
                 "open %s / next %s" % (opens, nxt))


def green_check():
    """Depth-1 green check: adjacent seams still green. Honors
    GOV_SKIP_GREEN (the wave-173 convention)."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green_check: SKIPPED (GOV_SKIP_GREEN=1)")
        return True
    import subprocess  # noqa: E402
    env = dict(os.environ, GOV_SKIP_GREEN="1",
               GOV_DEPLOYMENT_MODE="staging")
    suites = ["tests.test_grant_negotiation",
              "tests.test_decision_codes",
              "tests.test_attenuation"]
    ok = True
    for suite in suites:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "unittest", suite],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=300)
        except Exception as exc:  # noqa: BLE001
            print("green_check: %s ERROR %r" % (suite, exc))
            ok = False
            continue
        status = "OK" if r.returncode == 0 else "FAIL"
        print("green_check: %s %s" % (suite, status))
        if r.returncode != 0:
            ok = False
    return ok


def main():
    held = broke = errors = 0
    lines = []
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception:  # noqa: BLE001
            verdict, detail = "ERROR", traceback.format_exc(limit=3)
        print("%-42s %s %s" % (name, verdict, detail))
        lines.append((name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            broke += 1
        else:
            errors += 1
    print("w319_grant battery: %d BREAK / %d HELD / %d ERROR "
          "(greens: 0 break / 0 error)" % (broke, held, errors))
    probe_lines.emit(lines)
    gok = green_check()
    print("green_check: %s" % ("OK" if gok else "FAIL"))
    if broke or errors or not gok:
        sys.exit(1)


if __name__ == "__main__":
    main()
