#!/usr/bin/env python3
"""Wave-342 lane 4 battery: decision-code coverage campaign, round 4.

Round 3 (wave-341 lane B) moved the coverage table from 1950/2131 to
1982/2131 (149 gaps). This battery asserts the next 30 most
security-critical uncovered codes -- the refusal vocabulary on the
highest-adversarial-exploitability seams -- with real behavioral
probes (the hostile input is driven through the public seam and the
coded refusal is asserted), never tautologies. Each family carries a
discrimination control proving the probe distinguishes honest from
hostile input.

  G1  scan verdicts: scan_verdict_bad_verdict, scan_verdict_bad_digest,
      scan_verdict_bad_scanner_version, scan_verdict_unknown_scanner,
      scan_verdict_no_verifiers, scan_verdict_negative,
      scan_verdict_born_stale, scan_gate
  G2  refusal-vocabulary umbrellas (8 families): attenuation-refused,
      capsule-refused, posture-refused, permit-refused,
      hybrid-gate-refused, escalation-bind-refused, alg-refused,
      typed-action-refused -- each probed as: (a) a REAL family refusal
      is raised and caught under the umbrella base class (the public
      catch contract), (b) the umbrella literal is the base class's
      machine-readable code (what refusal-trail consumers read via
      getattr(exc, "code")), (c) the specific refusal's code differs
      from the umbrella (the umbrella is not vacuous), (d) the literal
      is registered in the central taxonomy
  G3  ratify node validation: ratify-policy-unsatisfied;
      pre-commit binding: precommit_refused
  G4  executor declaration check: contradictory_declaration,
      malformed_binding
  G5  deploy trust: bad-identity-policy (namespace promotion),
      subject-not-allowlisted (SCITT registration policy),
      ceremony-not-keyholder (root ceremony proposal)
  G6  MCP invocation authz: malformed-message, malformed-permit
  G7  tool-call policy: toolcall-regex-unsafe (backtracking gate)
  G8  evidence bundles: evidence-bundle-payload-type-refused
      (statement-error classifier), sigstore-keyed-malformed
      (structural check)
  G9  witness monitor: witness-alert-state-lost (F409 alert
      construction -- the exact builder the emission path uses)
  G10 offline verifier: offline-verify-anchor-unsupported
  P0  pin/taxonomy honesty (2134/2134/0 sorted-unique, footer state).
  PZ  green check (depth-1): adjacent suites as children with
      GOV_SKIP_GREEN=1.

Base: c47ab9e8 (wave-341 merge). Pin 2131, footer open F428 / next
F429. No gov/ changes in this lane. Findings: none filed (all probes
HELD on the base; a genuine BREAK would have been filed as F429+).

HYGIENE NOTE (not probes): five "uncovered" codes are dead base-class
defaults with no in-tree emission site and cannot be driven by any
input: admission-at-risk-accepted, single-use-refused,
evidence-refused, key-identity-refused, spiffe-refused. Left as gaps
for the registry-hygiene lane (wave-342 lane F), not probed here (a
probe that cannot go red is a tautology). Three more codes were
ranked out of the 30 for lower security criticality and remain gaps:
svr-refused (SVR records carry no authority by design),
bad-operator-ceremony (ceremony input validation),
witness-log-index-out-of-range (inclusion-proof bounds check),
malformed-context (third of three MCP malformed-input codes; the
other two are probed here).

Deterministic: fixed seeds and injected clocks; no assertion depends
on key material or the wall clock.
$0 spend by construction: this battery never touches the real-model
harness (grep-verified: no realmodel_harness/ModelDriver/provider).
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

TAXONOMY_PIN = 2134  # Wave-341 merge (c47ab9e8). Footer: open F429 / next F430.; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

FOOTER_OPEN = "F430, F431"
FOOTER_NEXT = "F432"

_results = []


def _held(pid, note):
    _results.append((pid, "HELD", note))


def _break(pid, note):
    _results.append((pid, "BREAK", note))


def _error(pid, note):
    _results.append((pid, "ERROR", note))


def _code_of(exc):
    """Extract the coded refusal from the exception, or None."""
    code = getattr(exc, "code", None)
    if isinstance(code, str) and code:
        return code
    reason = getattr(exc, "reason", None)
    if isinstance(reason, str) and reason:
        return reason
    msg = str(exc)
    head = msg.split(":", 1)[0].strip()
    if head and all(c.islower() or c.isdigit() or c in "-_." for c in head):
        return head
    return None


def _ensure_key():
    """Provision the deterministic test log key (pattern from
    evals/w339_attack_probes.py)."""
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


# ---------------------------------------------------------------------------
# P0: pin + taxonomy + footer honesty
# ---------------------------------------------------------------------------

def p0():
    from gov import decision_codes as dc
    codes = sorted(dc.TAXONOMY.keys())
    if len(codes) != TAXONOMY_PIN:
        _break("P0a", "taxonomy size %d != pin %d" % (len(codes), TAXONOMY_PIN))
    elif len(set(codes)) != len(codes):
        _break("P0a", "duplicate code literals in taxonomy")
    elif codes != sorted(set(codes)):
        _break("P0a", "taxonomy not sorted-unique")
    else:
        _held("P0a", "taxonomy 2134/2134/0 sorted-unique literals")
    footer = open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8").read()
    want = "Next free finding: **%s**. **Open findings: %s.**" % (
        FOOTER_NEXT, FOOTER_OPEN)
    if want in footer:
        _held("P0b", "footer open F429 / next F430")
    else:
        _break("P0b", "footer text mismatch")


# ---------------------------------------------------------------------------
# G1: scan verdicts
# ---------------------------------------------------------------------------

_G1_NOW = 1700000000
_G1_DIGEST = "sha256:" + "aa" * 32
_G1_RULESET = "sha256:" + "cc" * 32
_G1_SEED_A = bytes.fromhex("a1" * 32)
_G1_SEED_B = bytes.fromhex("b2" * 32)


def _g1_keys(seed):
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s = Ed25519Signer(seed)
    return s, [Ed25519Verifier(s.public_key)]


def _g1_emit(signer, **kw):
    from gov import scan_verdicts as sv
    args = dict(scanner_name="scanner-a", scanner_version="1.4.2",
                scan_target_digest=_G1_DIGEST, verdict="pass",
                ruleset_digest=_G1_RULESET, scanned_at=_G1_NOW - 3600,
                expires_at=_G1_NOW + 86400, signer=signer, now=_G1_NOW)
    args.update(kw)
    return sv.emit_scan_verdict(**args)


def g1():
    from gov import scan_verdicts as sv
    signer_a, verifiers_a = _g1_keys(_G1_SEED_A)
    signer_b, _ = _g1_keys(_G1_SEED_B)

    # G1a: scan_verdict_bad_verdict -- forged verdict vocabulary refused.
    try:
        _g1_emit(signer_a, verdict="banana")
        _break("G1a", "bad verdict did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_bad_verdict":
            _held("G1a", "forged verdict vocabulary refuses coded")
        else:
            _break("G1a", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: an honest verdict emits fine.
    try:
        _g1_emit(signer_a, verdict="pass")
        _held("G1a-disc", "honest 'pass' verdict emits (not vacuous)")
    except Exception as e:
        _break("G1a-disc", "honest verdict refused: %s" % e)

    # G1b: scan_verdict_bad_digest -- malformed digest pin refused, never coerced.
    try:
        _g1_emit(signer_a, scan_target_digest="nope-not-a-pin")
        _break("G1b", "malformed digest pin did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_bad_digest":
            _held("G1b", "malformed digest pin refuses coded")
        else:
            _break("G1b", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1b", "%s: %s" % (type(e).__name__, e))

    # G1c: scan_verdict_bad_scanner_version -- empty version refused.
    try:
        _g1_emit(signer_a, scanner_version="")
        _break("G1c", "empty scanner version did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_bad_scanner_version":
            _held("G1c", "empty scanner version refuses coded")
        else:
            _break("G1c", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1c", "%s: %s" % (type(e).__name__, e))

    # G1d: scan_verdict_unknown_scanner -- verdict from an unpinned scanner
    # is refused LOUD, never silently ignored.
    evil_env = _g1_emit(signer_b, scanner_name="scanner-evil")
    gate = sv.ScanGate(sv.ScanPolicy(["scanner-a"]),
                       {"scanner-a": verifiers_a})
    try:
        gate.check(_G1_DIGEST, [evil_env], now=_G1_NOW)
        _break("G1d", "unpinned-scanner verdict did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_unknown_scanner":
            _held("G1d", "unpinned scanner refuses LOUD coded")
        else:
            _break("G1d", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1d", "%s: %s" % (type(e).__name__, e))
    # Discrimination: the pinned scanner's verdict verifies through the gate.
    try:
        ok_env = _g1_emit(signer_a)
        out = gate.check(_G1_DIGEST, [ok_env], now=_G1_NOW)
        if out.get("ok"):
            _held("G1d-disc", "pinned scanner verifies (not vacuous)")
        else:
            _break("G1d-disc", "pinned verdict failed: %r" % out)
    except Exception as e:
        _break("G1d-disc", "pinned verdict raised: %s" % e)

    # G1e: scan_verdict_no_verifiers -- empty pinned keyset refused.
    env = _g1_emit(signer_a)
    try:
        sv.verify_scan_verdict(env, verifiers=[], scanner_name="scanner-a",
                               scan_target_digest=_G1_DIGEST, now=_G1_NOW)
        _break("G1e", "empty verifier set did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_no_verifiers":
            _held("G1e", "empty verifier set refuses coded")
        else:
            _break("G1e", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1e", "%s: %s" % (type(e).__name__, e))
    # Discrimination: the real keyset verifies.
    try:
        got = sv.verify_scan_verdict(env, verifiers=verifiers_a,
                                     scanner_name="scanner-a",
                                     scan_target_digest=_G1_DIGEST,
                                     now=_G1_NOW)
        if got["verified_key_ids"]:
            _held("G1e-disc", "pinned keyset verifies (not vacuous)")
        else:
            _break("G1e-disc", "no verified key ids")
    except Exception as e:
        _break("G1e-disc", "pinned verify raised: %s" % e)

    # G1f: scan_verdict_negative -- negative evidence dominates: a fail
    # verdict for a required scanner blocks promotion.
    fail_env = _g1_emit(signer_a, verdict="fail")
    try:
        gate.check(_G1_DIGEST, [fail_env], now=_G1_NOW)
        _break("G1f", "fail verdict did not block promotion")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_negative":
            _held("G1f", "fail verdict blocks promotion coded")
        else:
            _break("G1f", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1f", "%s: %s" % (type(e).__name__, e))

    # G1g: scan_verdict_born_stale -- a verdict born stale is refused.
    try:
        _g1_emit(signer_a, scanned_at=_G1_NOW - 7200,
                 expires_at=_G1_NOW - 3600)
        _break("G1g", "born-stale verdict did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_born_stale":
            _held("G1g", "born-stale verdict refuses coded")
        else:
            _break("G1g", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1g", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a fresh verdict emits fine.
    try:
        _g1_emit(signer_a, scanned_at=_G1_NOW - 10,
                 expires_at=_G1_NOW + 3600)
        _held("G1g-disc", "fresh verdict emits (not vacuous)")
    except Exception as e:
        _break("G1g-disc", "fresh verdict refused: %s" % e)

    # G1h: scan_gate -- verdicts must be a list of envelopes.
    try:
        gate.check(_G1_DIGEST, "notalist", now=_G1_NOW)
        _break("G1h", "non-list verdicts did not refuse")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_gate":
            _held("G1h", "non-list verdicts refuse coded scan_gate")
        else:
            _break("G1h", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1h", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a list proceeds past the shape check (fails later,
    # distinctly, on the missing required scanner).
    try:
        gate.check(_G1_DIGEST, [], now=_G1_NOW)
        _break("G1h-disc", "empty list unexpectedly passed")
    except sv.ScanVerdictError as e:
        if _code_of(e) == "scan_verdict_missing":
            _held("G1h-disc", "list shape passes; missing-scanner "
                              "refusal is distinct")
        else:
            _break("G1h-disc", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G1h-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G2: refusal-vocabulary umbrellas (8 families)
# ---------------------------------------------------------------------------

def _umbrella(pid, base_cls, sub_fn, sub_literal, umbrella_literal, family):
    """Probe one umbrella refusal-vocabulary code.

    (a) A REAL family refusal is raised and caught under the umbrella
    base class -- the public catch contract. (b) The umbrella literal
    is the base class's machine-readable code (what refusal-trail
    consumers read via getattr(exc, "code") for an unspecified family
    refusal). (c) The specific refusal's code differs from the
    umbrella (the umbrella is not vacuous). (d) The literal is
    registered in the central taxonomy.
    """
    from gov import decision_codes as dc
    try:
        sub_fn()
        _break(pid, "%s: real refusal did not raise" % family)
        return
    except base_cls as e:
        got = _code_of(e)
        if got != sub_literal:
            _break(pid, "%s: wrong sub code %r (want %r)"
                   % (family, got, sub_literal))
            return
    except Exception as e:
        _error(pid, "%s: unexpected %s: %s"
               % (family, type(e).__name__, e))
        return
    inst = base_cls("unspecified %s refusal" % family)
    if getattr(inst, "code", None) != umbrella_literal:
        _break(pid, "%s: umbrella contract broken: %r"
               % (family, getattr(inst, "code", None)))
        return
    if umbrella_literal not in dc.TAXONOMY:
        _break(pid, "%s: %r not in taxonomy"
               % (family, umbrella_literal))
        return
    _held(pid, "%s: family refuses coded (%s); umbrella vocabulary %r "
               "registered" % (family, sub_literal, umbrella_literal))


def g2():
    from gov import attenuation as att
    from gov import action_capsule as ac
    from gov import posture as po
    from gov import permit_leases as pl
    from gov import arap
    from gov import hybrid_gate as hg
    from gov import escalation_bind as eb
    from gov import alg_registry as ar
    from gov import typed_actions as ta

    # attenuation-refused: drive a real malformed-block refusal.
    _umbrella("G2a", att.AttenuationError,
              lambda: att._check_block_shape({}),
              "attenuation-unverifiable", "attenuation-refused",
              "attenuation")

    # capsule-refused: verify a non-dict capsule.
    _umbrella("G2b", ac.CapsuleError,
              lambda: ac.verify_capsule("not-a-dict"),
              "capsule-malformed", "capsule-refused",
              "action-capsule")

    # posture-refused: emit a signal for an unknown event.
    _umbrella("G2c", po.PostureError,
              lambda: po.emit_signal("bogus-event", "sub", "scope",
                                     b"0" * 32, issuer_id="iss1"),
              "signal-unknown-event", "posture-refused",
              "posture")

    # permit-refused: double-redeem a one-use permit.
    def _double_redeem():
        now = 1785000000
        key = b"w342-unit-test-key-0123456789abcdef"
        req = arap.new_request(request_id="r1", subject="alice",
                               resource="doc/1", action="read",
                               context={"amount": 100}, key=key)
        reg = pl.PermitRegistry(now=lambda: now)
        lease = reg.issue_for_arap(req, permit_id="u9", ttl_s=60)
        reg.redeem("u9", lease.parameter_digest)
        reg.redeem("u9", lease.parameter_digest)
    _umbrella("G2d", pl.PermitError, _double_redeem,
              "permit-reused", "permit-refused",
              "permit-lease")

    # hybrid-gate-refused: construct a family gate with a bad policy.
    _umbrella("G2e", hg.HybridGateError,
              lambda: hg.FamilyGate(policy="not-a-policy",
                                    key_registry={}),
              "hybrid-gate-malformed", "hybrid-gate-refused",
              "hybrid-gate")

    # escalation-bind-refused: bind with a non-dict capsule.
    _umbrella("G2f", eb.EscalationBindError,
              lambda: eb.bind_escalation({}, "not-a-dict"),
              "escalation-malformed", "escalation-bind-refused",
              "escalation-bind")

    # alg-refused: negotiate with no mutual algorithm.
    _umbrella("G2g", ar.AlgError,
              lambda: ar.negotiate_algorithms(["nope-a"], ["nope-b"]),
              "alg-no-mutual", "alg-refused",
              "alg-registry")

    # typed-action-refused: verify with a non-registry.
    _umbrella("G2h", ta.TypedActionError,
              lambda: ta.verify_typed_action({}, {}),
              "typed-action-malformed", "typed-action-refused",
              "typed-action")


# ---------------------------------------------------------------------------
# G3: ratify node validation + pre-commit binding
# ---------------------------------------------------------------------------

def g3():
    from gov import ratify as rat
    from gov import precommit as pco

    # G3a: ratify-policy-unsatisfied -- when the policy rollup fails
    # (a required verifier reports failure), the root node's results
    # carry the machine code "policy rollup: ratify-policy-unsatisfied".
    # Fail-closed as data: the enforcer never raises on outcomes.
    class _FailV(rat.Verifier):
        def verify(self, subject_bytes, metadata):
            return self._report(metadata, False, ["digest mismatch"])

    class _PassV(rat.Verifier):
        def verify(self, subject_bytes, metadata):
            return self._report(metadata, True, ["digest ok"])

    def _rollup(verifier):
        enf = rat.PolicyEnforcer()
        pol = rat.VerificationPolicy({"digest": "all"})
        return enf.verify(subject="tool-x",
                          subject_kind="tool-definition",
                          subject_bytes=b"bytes",
                          metadata={"subject": "tool-x"},
                          verifiers=[verifier], policy=pol)

    try:
        node = _rollup(_FailV("v1"))
        if any("policy rollup: ratify-policy-unsatisfied" in r
               for r in node["results"]):
            _held("G3a", "failed policy rollup reports coded")
        else:
            _break("G3a", "code absent from results: %r" % node["results"])
    except Exception as e:
        _error("G3a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a satisfied rollup reports "satisfied", not the
    # refusal code.
    try:
        node = _rollup(_PassV("v1"))
        if any("policy rollup: satisfied" in r for r in node["results"]) \
                and not any("ratify-policy-unsatisfied" in r
                            for r in node["results"]):
            _held("G3a-disc", "satisfied rollup is distinct (not vacuous)")
        else:
            _break("G3a-disc", "wrong results: %r" % node["results"])
    except Exception as e:
        _error("G3a-disc", "%s: %s" % (type(e).__name__, e))

    # G3b: precommit_refused -- approved preview A, executed B: the
    # commit binds the tool, so a tool swap refuses.
    gate = pco.PrecommitGate()
    preview = gate.preview("delete_file", {"path": "/x"})
    ticket = gate.approve(preview["preview_id"], "op-human")
    try:
        gate.commit(ticket["approval_id"], "send_email",
                    {"path": "/x"}, lambda: "ran")
        _break("G3b", "tool-swapped commit did not refuse")
    except pco.PrecommitRefused as e:
        if _code_of(e) == "precommit_refused":
            _held("G3b", "tool-swapped commit refuses coded")
        else:
            _break("G3b", "wrong code: %r" % _code_of(e))
    except Exception as e:
        _error("G3b", "%s: %s" % (type(e).__name__, e))
    # Discrimination: the approved tool executes.
    gate2 = pco.PrecommitGate()
    pv2 = gate2.preview("delete_file", {"path": "/x"})
    tk2 = gate2.approve(pv2["preview_id"], "op-human")
    try:
        out = gate2.commit(tk2["approval_id"], "delete_file",
                           {"path": "/x"}, lambda: "ran")
        if out == "ran":
            _held("G3b-disc", "matching commit executes (not vacuous)")
        else:
            _break("G3b-disc", "matching commit returned %r" % out)
    except Exception as e:
        _break("G3b-disc", "matching commit raised: %s" % e)


# ---------------------------------------------------------------------------
# G4: executor declaration check
# ---------------------------------------------------------------------------

def g4():
    from gov import executor as ex
    from gov import capability_gate as cg

    # G4a: contradictory_declaration -- binding AND ungoverned-ack is a
    # misconfiguration; fail closed rather than guess.
    log = []
    try:
        ex._capability_gate_construction_check(
            "run1", log, None, None, {"binding": "x"}, None, "ack reason")
        _break("G4a", "contradictory declarations did not refuse")
    except cg.CapabilityGateBindingError:
        causes = [ev.get("refusal_cause") for ev in log]
        if "contradictory_declaration" in causes:
            _held("G4a", "contradictory declarations refuse coded, "
                         "audited as contradictory_declaration")
        else:
            _break("G4a", "refusal not audited with the code: %r" % causes)
    except Exception as e:
        _error("G4a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: ack alone (no binding) is accepted, not refused.
    log2 = []
    try:
        out = ex._capability_gate_construction_check(
            "run2", log2, None, None, None, None, "ack reason")
        if out[2] == "ack reason":
            _held("G4a-disc", "ack-only declaration accepted (not vacuous)")
        else:
            _break("G4a-disc", "ack not recorded: %r" % (out,))
    except Exception as e:
        _break("G4a-disc", "ack-only raised: %s" % e)

    # G4b: malformed_binding -- a binding that fails validation refuses.
    log3 = []
    try:
        ex._capability_gate_construction_check(
            "run3", log3, None, None, {"bogus": 1}, None, None)
        _break("G4b", "malformed binding did not refuse")
    except cg.CapabilityGateBindingError:
        causes = [ev.get("refusal_cause") for ev in log3]
        if "malformed_binding" in causes:
            _held("G4b", "malformed binding refuses coded")
        else:
            _break("G4b", "refusal not audited with the code: %r" % causes)
    except Exception as e:
        _error("G4b", "%s: %s" % (type(e).__name__, e))
    # Discrimination: neither binding nor ack, no core -- raw pipeline,
    # untouched (returns Nones, no refusal).
    try:
        out = ex._capability_gate_construction_check(
            "run4", [], None, None, None, None, None)
        if out == (None, None, None):
            _held("G4b-disc", "raw pipeline untouched (not vacuous)")
        else:
            _break("G4b-disc", "unexpected: %r" % (out,))
    except Exception as e:
        _break("G4b-disc", "raw pipeline raised: %s" % e)


# ---------------------------------------------------------------------------
# G5: deploy trust (namespaces, SCITT, root ceremony)
# ---------------------------------------------------------------------------

_G5_SEED1 = bytes.fromhex("51" * 32)
_G5_SEED2 = bytes.fromhex("52" * 32)


def g5():
    from gov import sign_deploy_namespaces as sdn
    from gov.signing import Ed25519Signer, Ed25519Verifier
    from gov import scitt_receipt as sc
    from gov import root_ceremony as rc
    from gov import ballot_governance as bg

    # G5a: bad-identity-policy -- promote with a non-Policy
    # identity_policy refuses before any promotion.
    s1, s2 = Ed25519Signer(_G5_SEED1), Ed25519Signer(_G5_SEED2)
    verifiers = [Ed25519Verifier(s.public_key) for s in (s1, s2)]
    reg = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
    reg.stage("skill/x", b"bytes")
    reg.sign("skill/x", [s1])
    try:
        reg.promote("skill/x", operator_ids=["op-a", "op-b"],
                    identity_policy="not-a-policy")
        _break("G5a", "non-Policy identity_policy did not refuse")
    except sdn.NamespaceError as e:
        if e.code == "bad-identity-policy":
            _held("G5a", "non-Policy identity_policy refuses coded")
        else:
            _break("G5a", "wrong code: %r" % e.code)
    except Exception as e:
        _error("G5a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: promote without an identity policy succeeds.
    reg2 = sdn.NamespaceRegistry(verifiers=verifiers, threshold=1)
    reg2.stage("skill/y", b"bytes")
    reg2.sign("skill/y", [s1])
    try:
        out = reg2.promote("skill/y", operator_ids=["op-a", "op-b"])
        if out.get("status") == "promoted":
            _held("G5a-disc", "policy-less promote succeeds (not vacuous)")
        else:
            _break("G5a-disc", "unexpected: %r" % out)
    except Exception as e:
        _break("G5a-disc", "policy-less promote raised: %s" % e)

    # G5b: subject-not-allowlisted -- SCITT registration policy refuses
    # a subject outside the allowlist.
    policy = sc.RegistrationPolicy(
        name="p", version="1", allowed_issuers=("iss1",),
        allowed_subjects=("sub-ok",))
    body = {"issuer": "iss1", "subject": "sub-evil",
            "content_type": "x/y"}
    try:
        policy.check(body, b"bytes")
        _break("G5b", "non-allowlisted subject did not refuse")
    except sc.RegistrationRefused as e:
        if e.code == "subject-not-allowlisted":
            _held("G5b", "non-allowlisted subject refuses coded")
        else:
            _break("G5b", "wrong code: %r" % e.code)
    except Exception as e:
        _error("G5b", "%s: %s" % (type(e).__name__, e))
    # Discrimination: the allowlisted subject passes.
    try:
        ok_body = {"issuer": "iss1", "subject": "sub-ok",
                   "content_type": "x/y"}
        policy.check(ok_body, b"bytes")
        _held("G5b-disc", "allowlisted subject passes (not vacuous)")
    except Exception as e:
        _break("G5b-disc", "allowlisted subject raised: %s" % e)

    # G5c: ceremony-not-keyholder -- a root-ceremony proposal from a
    # non-keyholder refuses.
    member = bg.Member("alice", b"1" * 32)
    with tempfile.TemporaryDirectory() as td:
        journal = os.path.join(td, "journal.jsonl")
        gov = rc.CeremonyGovernor([member], journal)
        try:
            gov.propose("rotation", "rotate the root key", "ab" * 32,
                        "mallory", threshold=1, review_quorum=1)
            _break("G5c", "non-keyholder proposal did not refuse")
        except rc.CeremonyNotKeyholder as e:
            if e.code == "ceremony-not-keyholder":
                _held("G5c", "non-keyholder proposal refuses coded")
            else:
                _break("G5c", "wrong code: %r" % e.code)
        except Exception as e:
            _error("G5c", "%s: %s" % (type(e).__name__, e))
        # Discrimination: a keyholder's proposal is accepted.
        try:
            gov.propose("rotation", "rotate the root key", "cd" * 32,
                        "alice", threshold=1, review_quorum=1,
                        ceremony_id="c-disc")
            _held("G5c-disc", "keyholder proposal accepted (not vacuous)")
        except rc.CeremonyNotKeyholder as e:
            _break("G5c-disc", "keyholder wrongly refused: %s" % e)
        except Exception as e:
            _error("G5c-disc", "%s: %s" % (type(e).__name__, e))

# ---------------------------------------------------------------------------
# G6: MCP invocation authz
# ---------------------------------------------------------------------------

def g6():
    from gov import mcp_invocation_authz as mcp

    policy = mcp.McpInvocationPolicy(subject_id="svc-a",
                                     pinned_mapping_digest=None)

    # G6a: malformed-message -- authorize never raises on hostile input;
    # a non-mapping message refuses coded.
    try:
        res = mcp.authorize(policy, "not-a-mapping", {})
        if res.verdict == "refuse" and res.code == "malformed-message":
            _held("G6a", "non-mapping message refuses coded")
        else:
            _break("G6a", "wrong verdict/code: %r/%r"
                   % (res.verdict, res.code))
    except Exception as e:
        _error("G6a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a well-shaped message proceeds past the shape
    # check (fails later, distinctly, on the unpinned mapping).
    try:
        res = mcp.authorize(policy, {"method": "tools/call",
                                     "params": {}, "id": 1},
                            {"server_mapping": {"srv": "x"}})
        if res.code == "mapping-unpinned":
            _held("G6a-disc", "shaped message passes the shape check; "
                              "unpinned-mapping refusal is distinct")
        else:
            _break("G6a-disc", "wrong code: %r" % res.code)
    except Exception as e:
        _error("G6a-disc", "%s: %s" % (type(e).__name__, e))

    # G6b: malformed-permit -- apply_permit refuses a permit that is
    # not a valid invocation permit.
    try:
        res = mcp.apply_permit({"format": "wrong-format"}, {}, None)
        if res.verdict == "refuse" and res.code == "malformed-permit":
            _held("G6b", "invalid permit refuses coded")
        else:
            _break("G6b", "wrong verdict/code: %r/%r"
                   % (res.verdict, res.code))
    except Exception as e:
        _error("G6b", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a well-formed permit format proceeds past the
    # format check (fails later, distinctly, on the message digest).
    try:
        res = mcp.apply_permit({"format": mcp.FORMAT_PERMIT,
                                "message_digest": "sha256:" + "00" * 32},
                               {"method": "tools/call"}, None)
        if res.code == "permit-message-mismatch":
            _held("G6b-disc", "shaped permit passes the format check; "
                              "digest-mismatch refusal is distinct")
        else:
            _break("G6b-disc", "wrong code: %r" % res.code)
    except Exception as e:
        _error("G6b-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G7: tool-call policy (backtracking gate)
# ---------------------------------------------------------------------------

def _g7_doc(rules):
    return {
        "format": "sasanam-tool-call-policy/v1",
        "name": "w342-policy",
        "selector": {"agents": ["agent-a"]},
        "mode": "enforce",
        "rules": rules,
    }


def _g7_rule(**kw):
    rule = {"tool": "shell", "operation": "exec", "action": "ALLOW",
            "severity": 3, "message": "ok"}
    rule.update(kw)
    return rule


def g7():
    from gov import tool_call_policy as tcp

    # G7a: toolcall-regex-unsafe -- a backtracking-prone arg regex is a
    # caller-triggerable hang of the authorization decision; compile
    # refuses coded.
    evil = _g7_doc([_g7_rule(args={"cmd": {"regex": "(a+)+$"}})])
    try:
        tcp.compile_policy(evil)
        _break("G7a", "backtracking-prone regex did not refuse")
    except tcp.ToolCallPolicyError as e:
        if e.code == "toolcall-regex-unsafe":
            _held("G7a", "backtracking-prone regex refuses coded")
        else:
            _break("G7a", "wrong code: %r" % e.code)
    except Exception as e:
        _error("G7a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a safe regex compiles fine.
    safe = _g7_doc([_g7_rule(args={"cmd": {"regex": "^[a-z]+$"}})])
    try:
        tcp.compile_policy(safe)
        _held("G7a-disc", "safe regex compiles (not vacuous)")
    except Exception as e:
        _break("G7a-disc", "safe regex refused: %s" % e)


# ---------------------------------------------------------------------------
# G8: evidence bundles
# ---------------------------------------------------------------------------

def g8():
    from gov import evidence_sigstore as es
    from gov import sigstore_bundle as sb

    # G8a: evidence-bundle-payload-type-refused -- the statement-layer
    # refusal is classified onto the bundle-scoped taxonomy.
    try:
        got = es._classify_statement_error(
            Exception("payloadType mismatch: envelope carries 'x'"))
        if got == "evidence-bundle-payload-type-refused":
            _held("G8a", "payloadType mismatch classifies coded")
        else:
            _break("G8a", "wrong classification: %r" % got)
    except Exception as e:
        _error("G8a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: sibling messages classify to sibling codes, and
    # unknown messages fall back to malformed -- the classifier is not
    # a constant.
    try:
        sig = es._classify_statement_error(
            Exception("signature threshold not met: 0 of 1"))
        other = es._classify_statement_error(Exception("something else"))
        if sig == "evidence-bundle-signature-invalid" \
                and other == "evidence-bundle-malformed":
            _held("G8a-disc", "classifier distinguishes (not vacuous)")
        else:
            _break("G8a-disc", "wrong: %r / %r" % (sig, other))
    except Exception as e:
        _error("G8a-disc", "%s: %s" % (type(e).__name__, e))

    # G8b: sigstore-keyed-malformed -- a non-object bundle is refused
    # structurally, before any crypto.
    try:
        sb.check_keyed_bundle_structure("not-a-bundle")
        _break("G8b", "non-object bundle did not refuse")
    except sb.KeyedBundleError as e:
        if e.code == "sigstore-keyed-malformed":
            _held("G8b", "non-object bundle refuses coded")
        else:
            _break("G8b", "wrong code: %r" % e.code)
    except Exception as e:
        _error("G8b", "%s: %s" % (type(e).__name__, e))
    # Discrimination: the bool seam agrees -- a malformed bundle is
    # never a false success (False, never raises on bundle problems).
    try:
        if sb.verify_keyed_bundle("not-a-bundle", b"0" * 32) is False:
            _held("G8b-disc", "bool seam agrees: False, no false success")
        else:
            _break("G8b-disc", "bool seam returned non-False")
    except sb.KeyedBundleError:
        _break("G8b-disc", "bool seam raised on bundle problems")
    except Exception as e:
        _error("G8b-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G9: witness monitor (F409 alert construction)
# ---------------------------------------------------------------------------

def g9():
    from gov import monitor_alert as ma

    # G9a: witness-alert-state-lost -- when the alert-state file is gone
    # but the monitor has history, the loss is alerted LOUD with the
    # coded identity. Probe the exact alert builder the emission path
    # uses (_emit_loud -> _wrapper_error_alert).
    try:
        alert = ma._wrapper_error_alert(
            {"monitor_id": "m1"}, 12345,
            ma.WITNESS_ALERT_STATE_LOST, "state file missing")
        if alert.get("last_code") == "witness-alert-state-lost":
            _held("G9a", "state-loss alert carries the coded identity")
        else:
            _break("G9a", "wrong last_code: %r" % alert.get("last_code"))
    except Exception as e:
        _error("G9a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: a different alert kind carries a different code --
    # the builder is not a constant.
    try:
        alert = ma._wrapper_error_alert(
            {"monitor_id": "m1"}, 12345,
            ma.WITNESS_ALERT_WRAPPER_ERROR, "sink failed")
        if alert.get("last_code") == "witness-alert-wrapper-error":
            _held("G9a-disc", "alert builder distinguishes (not vacuous)")
        else:
            _break("G9a-disc", "wrong last_code: %r"
                   % alert.get("last_code"))
    except Exception as e:
        _error("G9a-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G10: offline verifier (anchor adapter)
# ---------------------------------------------------------------------------

def g10():
    from gov import offline_verify as OV

    # G10a: offline-verify-anchor-unsupported -- v1 verifies fake-log
    # receipts fully; any other adapter is fail-closed: the auditor
    # cannot verify what it cannot check.
    raw = {"anchor_receipt.json": b'{"adapter": "rekor"}'}
    manifest = {"anchor": {"adapter": "rekor"}}
    v = OV._Verifier({}, 1)
    try:
        v.check_anchor(raw, manifest)
        _break("G10a", "unsupported anchor adapter did not fail")
    except OV.OfflineVerifyError as e:
        if e.code == "offline-verify-anchor-unsupported":
            _held("G10a", "unsupported anchor adapter fails coded")
        else:
            _break("G10a", "wrong code: %r" % e.code)
    except Exception as e:
        _error("G10a", "%s: %s" % (type(e).__name__, e))
    # Discrimination: an adapter mismatch (receipt vs manifest) fails
    # earlier, distinctly -- the unsupported branch is specific.
    raw2 = {"anchor_receipt.json": b'{"adapter": "fake-log"}'}
    try:
        v.check_anchor(raw2, manifest)
        _break("G10a-disc", "adapter mismatch did not fail")
    except OV.OfflineVerifyError as e:
        if e.code == "offline-verify-anchor-invalid":
            _held("G10a-disc", "adapter mismatch fails distinctly "
                               "(not vacuous)")
        else:
            _break("G10a-disc", "wrong code: %r" % e.code)
    except Exception as e:
        _error("G10a-disc", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# PZ: green check (depth-1)
# ---------------------------------------------------------------------------

_EXPECTED_BREAKS = set()


def green_check():
    """Depth-1 green check: adjacent suites as children with
    GOV_SKIP_GREEN=1. Honored skip: records a skipped note."""
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _held("PZ", "green check skipped (GOV_SKIP_GREEN=1)")
        return
    suites = [
        "tests.test_scan_verdicts",
        "tests.test_mcp_invocation_authz",
        "tests.test_tool_call_policy",
        "tests.test_pack_loader",
        "tests.test_sign_deploy_namespaces",
        "tests.test_offline_verify",
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["GOV_DEPLOYMENT_MODE"] = "staging"
    bad = []
    for suite in suites:
        try:
            p = subprocess.run(
                [sys.executable, "-m", "unittest", suite, "-v"],
                cwd=REPO, env=env, capture_output=True, text=True,
                timeout=600)
            if p.returncode != 0:
                bad.append("%s rc=%d" % (suite, p.returncode))
        except Exception as e:
            bad.append("%s %s" % (suite, e))
    if bad:
        _break("PZ", "adjacent suite failures: %s" % "; ".join(bad))
    else:
        _held("PZ", "adjacent suites green: %s" % ", ".join(suites))


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

def main():
    _ensure_key()
    for fn in (p0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10):
        try:
            fn()
        except Exception:
            _error("main", "probe family %s crashed:\n%s"
                   % (fn.__name__, traceback.format_exc()))
    green_check()
    breaks = sorted(pid for pid, v, _ in _results if v == "BREAK")
    errors = sorted(pid for pid, v, _ in _results if v == "ERROR")
    held = sorted(pid for pid, v, _ in _results if v == "HELD")
    print("w342_covgap4: %d BREAK / %d HELD / %d ERROR"
          % (len(breaks), len(held), len(errors)))
    for pid, v, note in _results:
        if v != "HELD":
            print("  %s %s: %s" % (v, pid, note))
    if set(breaks) ^ _EXPECTED_BREAKS or errors:
        print("MISMATCH: got=%s want=%s errors=%s"
              % (breaks, sorted(_EXPECTED_BREAKS), errors))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
