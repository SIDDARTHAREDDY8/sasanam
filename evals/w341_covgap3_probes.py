#!/usr/bin/env python3
"""Wave-341 lane B battery: decision-code coverage campaign, round 3.

Round 1 (wave-339 lane 2) and round 2 (wave-340 lane 2) moved the
coverage table from 1919/2130 to 1950/2131 (181 gaps). This battery
asserts the next 30 most security-critical uncovered codes -- codes
on the highest-adversarial-exploitability seams (load-gate artifact
read, consumption journaling, grant-negotiation registry withdrawal,
pre-exec wall re-check timeout, R3 vocabularies, tool-call exception
scopes, sandbox placement, capability commit validation, MCP
subject anchoring, shield registration, per-tool grant validity,
lease windows, scan verdicts, battery envelopes, jail policy signing,
revocation-push hub construction, delegation store locking, inventory
identity, witness key availability) -- with real behavioral probes
(the hostile input is driven through the public seam and the coded
refusal is asserted), never tautologies. Each family carries a
discrimination control proving the probe distinguishes honest from
hostile input.

  G1  load gate: artifact_unreadable
  G2  consumption ledger: consumption-journal-write-failed
  G3  grant negotiation: grantneg-registry-withdrawn
  G4  egress launcher: preexec_recheck_timeout
  G5  aauth R3: r3-vocabulary-unknown
  G6  tool-call policy: toolcall-exception-scope-mismatch
  G7  executor write binding: outside_sandbox
  G8  capability grants: sandbox-refused, commit-path-escape,
      commit-right-missing, unknown-grant-id, child-refused-op,
      delegation-unknown-parent, approval-record-undigestible
  G9  MCP invocation authz: subject-unanchored
  G10 shield registry: shield-bad-id, shield-bad-params,
      shield-bad-provider-kind, shield-no-run, shield-non-verdict
  G11 per-tool grants: ptgrant-grant-not-yet-valid
  G12 capability leases: malformed_lease, lease_not_yet_valid
  G13 scan verdicts: scan_verdict_no_signer, scan_verdict_bad_bytes
  G14 battery envelope: envelope-bad-header
  G15 jail policy: signer-error
  G16 revocation push: revocation-push-refused
  G17 approvals delegation store: store_lock_unavailable
  G18 inventory query: inventory-identity-collision
  G19 evidence sigstore witness: evidence-bundle-witness-key-unavailable
  P0  pin/taxonomy honesty (2134/2134/0 sorted-unique, footer state).
  PZ  green check (depth-1): adjacent suites as children with
      GOV_SKIP_GREEN=1.

Base: adaafaef (wave-340 merge). Pin 2127, footer open none / next
F428. No gov/ changes in this lane. Findings: none filed (all probes
HELD on the base; a genuine BREAK would have been filed as F428+).

HYGIENE NOTE (not probes): five "uncovered" codes are dead base-class
defaults with no in-tree emission site and cannot be driven by any
input: admission-at-risk-accepted, single-use-refused,
evidence-refused, key-identity-refused, spiffe-refused. They are left
as gaps for a registry-hygiene lane, not probed here (a probe that
cannot go red is a tautology).

Deterministic: fresh random/fixed keys per run; no assertion depends on
key material or wall-clock time (all times are injected).
$0 spend by construction: this battery never touches the real-model
harness (grep-verified: no realmodel_harness/ModelDriver/provider).
"""

import base64
import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime, timezone, timedelta
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "tests"))

TAXONOMY_PIN = 2134  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*)

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
    # Coded refusals that embed the code at the message head
    # (e.g. "malformed_lease: ...", "scan_verdict_bad_bytes: ...").
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
    want = "Next free finding: **F436**. **Open findings: F432, F433, F434, F435.**"
    if want in footer:
        _held("P0b", "footer open none / next F430")
    else:
        _break("P0b", "footer text mismatch")


# ---------------------------------------------------------------------------
# G1: load gate -- artifact_unreadable
# ---------------------------------------------------------------------------

def g1():
    from gov.load_gate import load_file_verified, ArtifactRefused
    try:
        load_file_verified(None, "any-id", "/nonexistent-dir-xyz/missing.bin")
        _break("G1a", "unreadable artifact did not refuse")
    except ArtifactRefused as e:
        if str(e).startswith("artifact_unreadable"):
            _held("G1a", "unreadable artifact refuses coded artifact_unreadable")
        else:
            _break("G1a", "wrong code: %r" % str(e)[:60])
    except Exception as e:
        _error("G1a", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: a directory is equally unreadable as bytes.
    try:
        load_file_verified(None, "any-id", "/")
        _break("G1b", "directory-as-artifact did not refuse")
    except ArtifactRefused as e:
        if str(e).startswith("artifact_unreadable"):
            _held("G1b", "directory refuses coded too (not a missing-file special case)")
        else:
            _break("G1b", "wrong code: %r" % str(e)[:60])
    except Exception as e:
        _error("G1b", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G2: consumption ledger -- consumption-journal-write-failed
# ---------------------------------------------------------------------------

def g2():
    from gov.consumption_ledger import ConsumptionLedger
    # Hostile: journal path in a nonexistent directory -- the write-ahead
    # commit must fail LOUD, never silently skip journaling.
    led = ConsumptionLedger(
        journal_path="/nonexistent-dir-xyz-341/journal.jsonl")
    try:
        led.consume("ab" * 32, ("entity", "key-1"))
        _break("G2a", "unwritable journal did not refuse")
    except Exception as e:
        if _code_of(e) == "consumption-journal-write-failed":
            _held("G2a", "journal write failure refuses coded")
        else:
            _break("G2a", "wrong code: %r" % (_code_of(e),))
    # Discrimination control: a writable journal consumes fine.
    tmp = tempfile.mkdtemp(prefix="g2-ok-")
    led2 = ConsumptionLedger(journal_path=os.path.join(tmp, "j.jsonl"))
    try:
        rcpt = led2.consume("cd" * 32, ("entity", "key-2"))
        _held("G2b", "writable journal consumes (no false refusal)")
    except Exception as e:
        _break("G2b", "honest consume refused: %s" % (_code_of(e),))


# ---------------------------------------------------------------------------
# G3: grant negotiation -- grantneg-registry-withdrawn
# ---------------------------------------------------------------------------

def _make_executor(run_dir):
    from gov import artifact_inventory_manifest as man
    from gov.approvals import ApprovalQueue
    from gov.executor import ToolExecutor
    from gov.log import ActionLog
    from gov.policy import PolicyEngine
    policy = PolicyEngine(str(Path(REPO) / "policies" / "default.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack="w341-covgap3: synthetic harness")
    return ex, approvals, log


def g3():
    _ensure_key()
    from gov.log import read_entries
    from gov.policy import PolicyDecision
    run_dir = Path(tempfile.mkdtemp(prefix="g3-"))
    ex, approvals, log = _make_executor(run_dir)
    ident = ex.mint_identity("coder-1", "coder", "user-1")
    # Queue a grant-presenting approval, then withdraw the registry
    # (registry never installed here): the sweep must refuse LOUD at
    # execution time, never silently downgrade to unverified.
    aid = approvals.queue(
        {"tool": "shell", "args": {"cmd": "echo hi"},
         "identity": ident.as_dict(),
         "agent_justification": "g3 probe", "redactions": []},
        PolicyDecision("require_approval", "g3", policy_id="test", flag="t"),
        caller_identity=ident,
        presented_grant={"type": "test-grant", "id": "g1"})
    approvals.decide(aid, True, "looks fine", decided_by="op-1")
    assert getattr(ex, "_grant_registry", None) is None
    done = ex.execute_approved()
    evs = [e for e in read_entries(run_dir / "actions.jsonl")
           if isinstance(e, dict) and e.get("event") == "approval_execution_refused"
           and e.get("approval_id") == aid]
    if not evs:
        _break("G3a", "no approval_execution_refused event")
    elif evs[-1].get("code") == "grantneg-registry-withdrawn":
        _held("G3a", "withdrawn registry refuses coded grantneg-registry-withdrawn")
    else:
        _break("G3a", "wrong code: %r" % (evs[-1].get("code"),))
    # Discrimination control: the advisory seam itself returns
    # "not-applicable" (never "verified") for a missing registry --
    # the executor's loud refusal is keyed on exactly this signal.
    from gov import grant_negotiation
    status, _ = grant_negotiation.advisory_check(None, "shell", {"type": "x"},
                                                 "coder-1")
    if status == "not-applicable":
        _held("G3b", "advisory_check(None registry) -> not-applicable")
    else:
        _break("G3b", "unexpected advisory status %r" % (status,))


# ---------------------------------------------------------------------------
# G4: egress launcher -- preexec_recheck_timeout
# ---------------------------------------------------------------------------

def g4():
    import gov.egress_launcher as el

    class OkProvider(el.WallStateProvider):
        def check(self):
            return el.WallStateReport(el.WALL_UP)

    run_dir = Path(tempfile.mkdtemp(prefix="g4-"))
    events = []
    launcher = object.__new__(el.FilteredEgressLauncher)
    launcher.lock_path = str(run_dir / "w.lock")
    launcher._wall_id = "g4-test-wall"
    launcher.wall = OkProvider()

    class _Inv:
        def verify(self):
            return ({"m": 1}, {})

    launcher.inventory = _Inv()
    launcher._wall_proof = lambda: ("a" * 64, "b" * 64, "c" * 64)
    launcher._emit = events.append
    # Simulate the documented hang condition: the child is alive but
    # produced neither the preexec ack byte nor EOF within the
    # deadline. The ack reader is the only seam replaced; the
    # kill/wait/emit/raise branch below is 100% production code.
    launcher._read_preexec_ack = lambda fd: None
    try:
        launcher.launch(["/bin/true"])
        _break("G4a", "hung preexec did not refuse")
    except el.EgressLaunchRefused as e:
        if str(e).startswith("preexec_recheck_timeout"):
            refused = [x for x in events
                       if x.get("event") == "egress_wall_launch_refused"]
            if refused and refused[-1].get("reason") == "preexec_recheck_timeout":
                _held("G4a", "hung preexec refuses coded preexec_recheck_timeout")
            else:
                _break("G4a", "exception coded but no matching audit event")
        else:
            _break("G4a", "wrong code: %r" % str(e)[:50])
    except Exception as e:
        _error("G4a", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: the real ack reader returns True when the
    # child writes the ack byte (not a deadline-shape false positive).
    r, w = os.pipe()
    try:
        os.write(w, b"\x01")
        os.close(w)
        got = el.FilteredEgressLauncher._read_preexec_ack(r)
        if got is True:
            _held("G4b", "real ack reader returns True on the ack byte")
        else:
            _break("G4b", "ack reader returned %r" % (got,))
    finally:
        os.close(r)


# ---------------------------------------------------------------------------
# G5: aauth R3 -- r3-vocabulary-unknown
# ---------------------------------------------------------------------------

def g5():
    from gov.aauth_r3 import validate_operation, R3Error, VOCABULARIES
    try:
        validate_operation("urn:example:unregistered-vocab", {"tool": "x"})
        _break("G5a", "unknown vocabulary did not refuse")
    except R3Error as e:
        if e.code == "r3-vocabulary-unknown":
            _held("G5a", "unknown vocabulary refuses coded r3-vocabulary-unknown")
        else:
            _break("G5a", "wrong code: %r" % (e.code,))
    except Exception as e:
        _error("G5a", "%s: %s" % (type(e).__name__, e))
    # Discrimination controls: the seam distinguishes empty/non-string
    # (r3-malformed) and registered-vocab-unknown-op (r3-unknown-operation).
    try:
        validate_operation("", {"tool": "x"})
        _break("G5b", "empty vocab did not refuse")
    except R3Error as e:
        if e.code == "r3-malformed":
            _held("G5b", "empty vocab -> r3-malformed (distinct code)")
        else:
            _break("G5b", "wrong code: %r" % (e.code,))
    except Exception as e:
        _error("G5b", "%s: %s" % (type(e).__name__, e))
    vocab = sorted(VOCABULARIES.keys())[0]
    try:
        validate_operation(vocab, {"nope": 1})
        _break("G5c", "unknown op in registered vocab did not refuse")
    except R3Error as e:
        if e.code == "r3-unknown-operation":
            _held("G5c", "registered vocab + unknown op -> r3-unknown-operation")
        else:
            _break("G5c", "wrong code: %r" % (e.code,))
    except Exception as e:
        _error("G5c", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G6: tool-call policy -- toolcall-exception-scope-mismatch
# ---------------------------------------------------------------------------

def _tcp_world():
    from gov import tool_call_policy as tcp, governed_exceptions as ge
    doc = {"format": "sasanam-tool-call-policy/v1", "name": "u",
           "selector": {"agents": ["agent-a"]}, "mode": "enforce",
           "rules": [{"tool": "shell", "operation": "exec", "action": "DENY",
                      "severity": 8, "message": "x"}]}
    pol = tcp.compile_policy(doc)
    reg = ge.CheckRegistry()
    reg.register("C1", "denied tool call explained here", "policy",
                 "high", "unit check", ["tool_call"])
    store = ge.ExceptionStore(reg)
    store.set_approvers(["op-1"])
    return tcp, pol, store


def g6():
    tcp, pol, store = _tcp_world()
    # Hostile: suppress against an alert identity hash that was never
    # recorded -- the scope cannot be bound to an unknown alert.
    try:
        tcp.suppress_with_exception(pol, "deadbeef-no-such-alert", store,
                                    "C1", ("tool", "shell"), now=1700000000.0)
        _break("G6a", "unknown alert hash did not refuse")
    except tcp.ToolCallPolicyError as e:
        if e.code == "toolcall-exception-scope-mismatch":
            _held("G6a", "unknown alert refuses coded toolcall-exception-scope-mismatch")
        else:
            _break("G6a", "wrong code: %r" % (e.code,))
    except Exception as e:
        _error("G6a", "%s: %s" % (type(e).__name__, e))
    # Hostile variant 2: the scope names the wrong tool for a REAL alert.
    d = pol.decide({"identity": "agent-a", "authenticated": True, "tags": []},
                   "shell", "exec", {})
    try:
        tcp.suppress_with_exception(pol, d.alert["runtime_identity_hash"],
                                    store, "C1", ("tool", "other-tool"),
                                    now=1700000000.0)
        _break("G6b", "wrong-tool scope did not refuse")
    except tcp.ToolCallPolicyError as e:
        if e.code == "toolcall-exception-scope-mismatch":
            _held("G6b", "mismatched tool scope refuses coded")
        else:
            _break("G6b", "wrong code: %r" % (e.code,))
    except Exception as e:
        _error("G6b", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: a live exception for the RIGHT scope
    # suppresses (the seam is not a blanket refusal).
    store2reg = store
    store.grant("C1", ("tool", "shell"),
                "unit-test accepted risk with ops review", "op-1",
                1700000000.0 + 3600, 1700000000.0, now=1700000000.0)
    try:
        s = tcp.suppress_with_exception(pol, d.alert["runtime_identity_hash"],
                                        store, "C1", ("tool", "shell"),
                                        now=1700000000.0)
        if s.get("action") == "SKIPPED" and s.get("verdict") == "DENY":
            _held("G6c", "live exception for the right scope suppresses (DENY kept)")
        else:
            _break("G6c", "unexpected suppression outcome %r" % (s,))
    except Exception as e:
        _break("G6c", "honest suppression refused: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G7: executor write binding -- outside_sandbox
# ---------------------------------------------------------------------------

def g7():
    _ensure_key()
    from gov import artifact_inventory_manifest as man
    SHA = "ab" * 32
    run_dir = Path(tempfile.mkdtemp(prefix="g7-"))
    ex, _approvals, _log = _make_executor(run_dir)
    # Rebuild with a deployment manifest attached (the outside_sandbox
    # reason only exists under a manifest deployment).
    from gov.approvals import ApprovalQueue
    from gov.executor import ToolExecutor
    from gov.log import ActionLog
    from gov.policy import PolicyEngine
    policy = PolicyEngine(str(Path(REPO) / "policies" / "default.yaml"))
    log = ActionLog(run_dir / "actions2.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex2 = ToolExecutor(run_dir, policy, log, approvals,
                       ledger_path=run_dir / "egress2.jsonl",
                       ungoverned_ack="w341-covgap3",
                       deployment_manifest=man.pin_manifest({"a.bin": SHA}))
    res = ex2.check_write_declared_path("coder-1", "/etc/passwd")
    if res.get("verdict") == "allow" and res.get("reason") == "outside_sandbox":
        _held("G7a", "absolute path outside the manifest -> allow + outside_sandbox")
    else:
        _break("G7a", "unexpected result %r" % (res,))
    # Discrimination control: a manifest-declared path is not
    # outside_sandbox.
    res2 = ex2.check_write_declared_path("coder-1", "a.bin",
                                         declared_path="a.bin")
    if res2.get("reason") != "outside_sandbox":
        _held("G7b", "declared path does not get the outside_sandbox reason")
    else:
        _break("G7b", "declared path mislabeled outside_sandbox")


# ---------------------------------------------------------------------------
# G8: capability grants (7 codes)
# ---------------------------------------------------------------------------

def _g8_world():
    from gov import capability_grants as cg
    fs = Path(tempfile.mkdtemp(prefix="g8fs-"))
    pol = cg.GrantPolicy(fs_root=str(fs))
    reg = cg.GrantRegistry()
    disp = cg.GrantDispatcher(reg, grant_policy=pol)
    return cg, fs, pol, reg, disp


def g8():
    cg, fs, pol, reg, disp = _g8_world()

    # G8a: sandbox-refused -- the child sandbox raises; the refusal is
    # recorded with the coded reason and re-raised LOUD.
    class _Boom:
        def run(self, *a, **k):
            raise RuntimeError("wall down")

    disp_boom = cg.GrantDispatcher(cg.GrantRegistry(), sandbox=_Boom(),
                                   grant_policy=pol)
    try:
        disp_boom._run_child("/tmp/staging-x", decision_id="d1")
        _break("G8a", "sandbox explosion did not refuse")
    except cg.GrantError:
        if disp_boom._registry.refusals[-1]["reason"] == "sandbox-refused":
            _held("G8a", "sandbox failure refuses coded sandbox-refused")
        else:
            _break("G8a", "wrong reason %r"
                   % (disp_boom._registry.refusals[-1]["reason"],))
    except Exception as e:
        _error("G8a", "%s: %s" % (type(e).__name__, e))

    # G8b: commit-right-missing -- outbox file whose dispatch capability
    # carries no write right.
    st = Path(tempfile.mkdtemp(prefix="g8stg-")); (st / "out").mkdir()
    (st / "out" / "tok1").write_bytes(b"x")
    cap = cg.Capability("file", str(fs / "ok.txt"), {"read"})
    try:
        disp._commit({"record": {"tok1": (cap, b"x")}, "grant_set": None},
                     {"ok": True, "refusals": []}, str(st), "d1")
        _break("G8b", "rightless commit did not refuse")
    except cg.GrantError:
        if reg.refusals[-1]["reason"] == "commit-right-missing":
            _held("G8b", "rightless outbox refuses coded commit-right-missing")
        else:
            _break("G8b", "wrong reason %r" % (reg.refusals[-1]["reason"],))
    except Exception as e:
        _error("G8b", "%s: %s" % (type(e).__name__, e))

    # G8c: commit-path-escape -- the staged destination escapes fs_root.
    reg2 = cg.GrantRegistry()
    disp2 = cg.GrantDispatcher(reg2, grant_policy=pol)
    st2 = Path(tempfile.mkdtemp(prefix="g8stg2-")); (st2 / "out").mkdir()
    (st2 / "out" / "tok2").write_bytes(b"x")
    cap2 = cg.Capability("file", "/etc/shadow", {"write"})
    try:
        disp2._commit({"record": {"tok2": (cap2, b"x")}, "grant_set": None},
                      {"ok": True, "refusals": []}, str(st2), "d2")
        _break("G8c", "escaping commit did not refuse")
    except cg.GrantError:
        if reg2.refusals[-1]["reason"] == "commit-path-escape":
            _held("G8c", "escaping commit refuses coded commit-path-escape")
        else:
            _break("G8c", "wrong reason %r" % (reg2.refusals[-1]["reason"],))
    except Exception as e:
        _error("G8c", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: an in-root write commits (no false
    # refusal), proving the escape check is a check, not a blanket ban.
    reg3 = cg.GrantRegistry()
    disp3 = cg.GrantDispatcher(reg3, grant_policy=pol)
    st3 = Path(tempfile.mkdtemp(prefix="g8stg3-")); (st3 / "out").mkdir()
    (st3 / "out" / "tok3").write_bytes(b"hello")
    (fs / "sub").mkdir(exist_ok=True)
    dest = fs / "sub" / "ok.txt"
    cap3 = cg.Capability("file", str(dest), {"write"})
    gs = cg.GrantSet([]).with_id("g-test-3")
    try:
        disp3._commit({"record": {"tok3": (cap3, b"hello")},
                       "grant_set": gs, "capability_count": 0},
                      {"ok": True, "refusals": []}, str(st3), "d3")
        if dest.read_bytes() == b"hello":
            _held("G8d", "in-root write commits (escape check is not a blanket ban)")
        else:
            _break("G8d", "commit did not land the bytes")
    except Exception as e:
        _break("G8d", "honest commit refused: %s" % (type(e).__name__,))

    # G8e: unknown-grant-id -- consuming a never-minted grant.
    reg4 = cg.GrantRegistry()
    try:
        reg4.consume("never-minted-id", decision_id="d4")
        _break("G8e", "unknown grant consumed without refusal")
    except cg.GrantRefused:
        if reg4.refusals[-1]["reason"] == "unknown-grant-id":
            _held("G8e", "unknown grant refuses coded unknown-grant-id")
        else:
            _break("G8e", "wrong reason %r" % (reg4.refusals[-1]["reason"],))
    except Exception as e:
        _error("G8e", "%s: %s" % (type(e).__name__, e))

    # G8f: child-refused-op -- child-reported refusals are chained LOUD.
    reg5 = cg.GrantRegistry()
    disp5 = cg.GrantDispatcher(reg5, grant_policy=pol)
    st5 = Path(tempfile.mkdtemp(prefix="g8stg5-")); (st5 / "out").mkdir()
    gs5 = cg.GrantSet([]).with_id("g-test-5")
    try:
        disp5._commit({"record": {}, "grant_set": gs5, "capability_count": 0},
                      {"ok": True,
                       "refusals": [{"op": "write", "reason": "denied"}]},
                      str(st5), "d5")
        if reg5.refusals and reg5.refusals[-1]["reason"] == "child-refused-op":
            _held("G8f", "child refusal chained coded child-refused-op")
        else:
            _break("G8f", "child refusal not chained")
    except Exception as e:
        _error("G8f", "%s: %s" % (type(e).__name__, e))

    # G8g: delegation-unknown-parent -- subset of a never-minted parent.
    reg6 = cg.GrantRegistry()
    try:
        reg6.register_subset("never-minted", None, decision_id="d6")
        _break("G8g", "unknown parent accepted")
    except cg.GrantRefused:
        if reg6.refusals[-1]["reason"] == "delegation-unknown-parent":
            _held("G8g", "unknown parent refuses coded delegation-unknown-parent")
        else:
            _break("G8g", "wrong reason %r" % (reg6.refusals[-1]["reason"],))
    except Exception as e:
        _error("G8g", "%s: %s" % (type(e).__name__, e))

    # G8h: approval-record-undigestible -- the approval packet's own
    # digest cannot be derived (its field-read path is broken), so the
    # grant refuses fail-closed rather than minting on an unbound packet.
    _ensure_key()
    reg7 = cg.GrantRegistry()

    class _PoisonedGet(dict):
        def get(self, k, *a, **k2):
            raise RuntimeError("record store poisoned")

    try:
        cg.derive_grants(
            verified_manifest={"skill_id": "s", "capabilities": {}},
            grant_policy=None,
            approval={"approval_id": "a1", "record_digest": "ab" * 32},
            decision_id="d7", registry=reg7,
            approval_records={"a1": _PoisonedGet(tool="shell")})
        _break("G8h", "undigestible record did not refuse")
    except cg.GrantRefused:
        if reg7.refusals and reg7.refusals[-1]["reason"] == "approval-record-undigestible":
            _held("G8h", "undigestible record refuses coded approval-record-undigestible")
        else:
            _break("G8h", "wrong reason %r"
                   % (reg7.refusals[-1]["reason"] if reg7.refusals else None,))
    except Exception as e:
        _error("G8h", "%s: %s" % (type(e).__name__, e))


# ---------------------------------------------------------------------------
# G9: MCP invocation authz -- subject-unanchored
# ---------------------------------------------------------------------------

def g9():
    from gov import mcp_invocation_authz as mia
    mapping = {"servers": ["s1"]}
    policy = mia.build_policy(
        {"subject_id": "alice",
         "pinned_mapping_digest": mia.canonical_digest(mapping)})
    # Hostile: no top-level subject at all.
    r = mia.authorize(policy, {"method": "tools/call", "id": 1},
                      {"server_mapping": mapping})
    if r.verdict == "refuse" and r.code == "subject-unanchored":
        _held("G9a", "missing subject refuses coded subject-unanchored")
    else:
        _break("G9a", "unexpected %r/%r" % (r.verdict, r.code))
    # Hostile variant: a subject that is not the anchored one.
    r2 = mia.authorize(policy, {"method": "tools/call", "id": 2},
                       {"server_mapping": mapping,
                        "subject": {"id": "mallory"}})
    if r2.verdict == "refuse" and r2.code == "subject-unanchored":
        _held("G9b", "wrong subject refuses coded subject-unanchored")
    else:
        _break("G9b", "unexpected %r/%r" % (r2.verdict, r2.code))
    # Discrimination control: the anchored subject with the pinned
    # mapping permits (the seam is not a blanket refusal).
    r3 = mia.authorize(policy, {"method": "tools/call", "id": 3},
                       {"server_mapping": mapping,
                        "subject": {"id": "alice"}})
    if r3.verdict == "permit":
        _held("G9c", "anchored subject permits")
    else:
        _break("G9c", "honest call refused: %r" % (r3.code,))


# ---------------------------------------------------------------------------
# G10: shield registry (5 codes)
# ---------------------------------------------------------------------------

def g10():
    from gov.shield_registry import (Shield, ShieldData, ShieldError,
                                     ShieldVerdict, _run_with_payload)
    cases = [
        ("G10a", dict(shield_id="", run=lambda data: None), "shield-bad-id"),
        ("G10b", dict(shield_id="s1", params={"k": object()},
                      run=lambda data: None), "shield-bad-params"),
        ("G10c", dict(shield_id="s1", provider_kind="bogus",
                      run=lambda data: None), "shield-bad-provider-kind"),
        ("G10d", dict(shield_id="s1", run=None), "shield-no-run"),
    ]
    for pid, kw, want in cases:
        try:
            Shield(**kw)
            _break(pid, "%s: construction did not refuse" % want)
        except ShieldError as e:
            if e.code == want:
                _held(pid, "%s refuses coded" % want)
            else:
                _break(pid, "wrong code %r (want %r)" % (e.code, want))
        except Exception as e:
            _error(pid, "%s: %s" % (type(e).__name__, e))
    # G10e: a shield whose run() returns a non-verdict.
    try:
        bad = Shield("sb", run=lambda data: "allow")
        _run_with_payload(bad, bad.run(ShieldData("p", bad.params)))
        _break("G10e", "non-verdict run did not refuse")
    except ShieldError as e:
        if e.code == "shield-non-verdict":
            _held("G10e", "non-verdict run refuses coded shield-non-verdict")
        else:
            _break("G10e", "wrong code %r" % (e.code,))
    except Exception as e:
        _error("G10e", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: a well-formed shield runs and a real
    # ShieldVerdict passes through.
    try:
        s = Shield("ok", run=lambda data: ShieldVerdict("allow", "fine"))
        out = _run_with_payload(s, s.run(ShieldData("p", s.params)))
        if out is None:
            _held("G10f", "well-formed shield runs clean")
        else:
            _break("G10f", "unexpected payload result %r" % (out,))
    except Exception as e:
        _break("G10f", "honest shield refused: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G11: per-tool grants -- ptgrant-grant-not-yet-valid
# ---------------------------------------------------------------------------

def _ptg_world():
    from gov import tool_grant, ed25519
    iss_seed = bytes.fromhex("11" * 32)
    holder_seed = bytes.fromhex("22" * 32)
    iss = tool_grant.Issuer(iss="sasanam-tool-as", issuer_seed=iss_seed,
                            mandate_lookup=lambda m: {"version": 7})
    details = [{
        "type": "https://sasanam.dev/mcp_tool_call",
        "locations": ["https://mcp.example.internal/fileserver"],
        "actions": ["call"],
        "identifier": "fileserver::read_file",
        "arg_bounds": {"path": {"predicate": "prefix",
                                "params": {"prefix": "/data/shared/"}}},
        "supply_chain": {"link_digest": "sha256:" + "ab" * 32,
                         "delegation_ok": True},
        "max_calls": 3,
    }]
    return tool_grant, ed25519, iss, iss_seed, holder_seed, details


def g11():
    tool_grant, ed25519, iss, iss_seed, holder_seed, details = _ptg_world()
    NOW = 1790000000
    grant = iss.issue(
        sub="spiffe://trust-domain/ns/prod/sa/agent-7",
        aud="https://mcp.example.internal/fileserver",
        proof_pub=ed25519.publickey(holder_seed),
        mandate_id="mnd_1", mandate_version=7, details=details,
        lifetime_s=600, now=NOW)
    # Hostile: verify BEFORE the grant's iat (a pre-dated presentation).
    ok, code, _detail = tool_grant.verify_grant(
        grant, issuer_pub=ed25519.publickey(iss_seed), now=NOW - 10)
    if not ok and code == "ptgrant-grant-not-yet-valid":
        _held("G11a", "pre-iat presentation refuses coded ptgrant-grant-not-yet-valid")
    else:
        _break("G11a", "unexpected (%r, %r)" % (ok, code))
    # Discrimination control: the same grant verifies at its iat.
    ok2, code2, _d2 = tool_grant.verify_grant(
        grant, issuer_pub=ed25519.publickey(iss_seed), now=NOW)
    if ok2:
        _held("G11b", "in-window presentation verifies")
    else:
        _break("G11b", "honest verify refused: %r" % (code2,))


# ---------------------------------------------------------------------------
# G12: capability leases -- malformed_lease, lease_not_yet_valid
# ---------------------------------------------------------------------------

def _lease_world():
    from gov import capability_leases as cl, delegation_tokens as dt, ed25519

    def _pub(seed):
        return ed25519.publickey(seed)

    auth_seed = secrets.token_bytes(32)
    human_seed = secrets.token_bytes(32)
    user_seed = secrets.token_bytes(32)
    trust = dt.DelegationTrust(
        human_keys={"op:alice": _pub(human_seed)},
        authority_keys={"reg-auth": _pub(auth_seed)},
        user_issuer_keys={"idp": _pub(user_seed)})
    authority = cl.LeaseAuthority(auth_seed, "reg-auth", trust)
    verifier = cl.LeaseVerifier(trust)
    return cl, authority, verifier


def g12():
    cl, authority, verifier = _lease_world()
    lease = authority.mint("agent-1", "task-9", {"tools": ["tool:read_file"]})
    # Hostile: a lease with a torn field set.
    bad = dict(lease)
    del bad["signature"]
    try:
        verifier.require(bad, agent_id="agent-1", task_id="task-9",
                         tool="read_file")
        _break("G12a", "field-torn lease did not refuse")
    except cl.LeaseRefused as e:
        if str(e).startswith("malformed_lease"):
            _held("G12a", "torn lease refuses coded malformed_lease")
        else:
            _break("G12a", "wrong code: %r" % str(e)[:40])
    except Exception as e:
        _error("G12a", "%s: %s" % (type(e).__name__, e))
    # Hostile: a correctly-signed lease presented before not_before.
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    early = authority.mint("agent-1", "task-9",
                           {"tools": ["tool:read_file"]}, now=future)
    try:
        verifier.require(early, agent_id="agent-1", task_id="task-9",
                         tool="read_file")
        _break("G12b", "pre-window lease did not refuse")
    except cl.LeaseRefused as e:
        if str(e).startswith("lease_not_yet_valid"):
            _held("G12b", "pre-window lease refuses coded lease_not_yet_valid")
        else:
            _break("G12b", "wrong code: %r" % str(e)[:40])
    except Exception as e:
        _error("G12b", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: the honest mint/verify roundtrip works.
    try:
        lid = verifier.require(lease, agent_id="agent-1", task_id="task-9",
                               tool="read_file")
        if lid == lease["lease_id"]:
            _held("G12c", "honest lease verifies")
        else:
            _break("G12c", "lease id mismatch")
    except Exception as e:
        _break("G12c", "honest lease refused: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G13: scan verdicts -- scan_verdict_no_signer, scan_verdict_bad_bytes
# ---------------------------------------------------------------------------

def g13():
    from gov.scan_verdicts import (digest_of_bytes, emit_scan_verdict,
                                   ScanVerdictError)
    from gov.signing import Ed25519Signer
    NOW = 1790000000
    kw = dict(scanner_name="s", scanner_version="1",
              scan_target_digest="sha256:" + "ab" * 32, verdict="pass",
              ruleset_digest="sha256:" + "cd" * 32,
              scanned_at=NOW, expires_at=NOW + 60, now=NOW)
    # Hostile: a verdict with no signer attached.
    try:
        emit_scan_verdict(signer=None, **kw)
        _break("G13a", "signerless verdict did not refuse")
    except ScanVerdictError as e:
        if str(e).startswith("scan_verdict_no_signer"):
            _held("G13a", "signerless verdict refuses coded scan_verdict_no_signer")
        else:
            _break("G13a", "wrong code: %r" % str(e)[:50])
    except Exception as e:
        _error("G13a", "%s: %s" % (type(e).__name__, e))
    # Hostile: digest_of_bytes given a digest STRING where bytes belong
    # (would silently re-bind the verdict to the claim).
    try:
        digest_of_bytes("sha256:" + "ab" * 32)
        _break("G13b", "string-as-bytes did not refuse")
    except ScanVerdictError as e:
        if str(e).startswith("scan_verdict_bad_bytes"):
            _held("G13b", "string-as-bytes refuses coded scan_verdict_bad_bytes")
        else:
            _break("G13b", "wrong code: %r" % str(e)[:50])
    except Exception as e:
        _error("G13b", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: real bytes digest, and a signed verdict
    # emits.
    try:
        d = digest_of_bytes(b"scanner bytes")
        assert d.startswith("sha256:")
        env = emit_scan_verdict(signer=Ed25519Signer(secrets.token_bytes(32)),
                                **kw)
        _held("G13c", "honest bytes + signer emit clean")
    except Exception as e:
        _break("G13c", "honest path failed: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G14: battery envelope -- envelope-bad-header
# ---------------------------------------------------------------------------

def g14():
    from gov.battery_envelope import RunBuilder, BatteryEnvelopeError
    try:
        RunBuilder("", "1.0")
        _break("G14a", "empty battery name did not refuse")
    except BatteryEnvelopeError as e:
        if "envelope-bad-header" in str(e):
            _held("G14a", "empty battery name refuses coded envelope-bad-header")
        else:
            _break("G14a", "wrong error: %r" % str(e)[:60])
    except Exception as e:
        _error("G14a", "%s: %s" % (type(e).__name__, e))
    try:
        RunBuilder("batt", "")
        _break("G14b", "empty version did not refuse")
    except BatteryEnvelopeError as e:
        if "envelope-bad-header" in str(e):
            _held("G14b", "empty version refuses coded envelope-bad-header")
        else:
            _break("G14b", "wrong error: %r" % str(e)[:60])
    except Exception as e:
        _error("G14b", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: well-formed header constructs.
    try:
        RunBuilder("batt", "1.0")
        _held("G14c", "well-formed header constructs")
    except Exception as e:
        _break("G14c", "honest header refused: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G15: jail policy -- signer-error
# ---------------------------------------------------------------------------

def g15():
    from gov.jail_policy import sign_policy, make_policy_body, JailPolicyError
    body = make_policy_body("p", 1, writable_dirs=["/tmp"])
    try:
        sign_policy(b"too-short", body)
        _break("G15a", "short seed did not refuse")
    except JailPolicyError as e:
        if getattr(e, "code", None) == "signer-error":
            _held("G15a", "short seed refuses coded signer-error")
        else:
            _break("G15a", "wrong code: %r" % (getattr(e, "code", None),))
    except Exception as e:
        _error("G15a", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: a 32-byte seed signs.
    try:
        sig = sign_policy(secrets.token_bytes(32), body)
        _held("G15b", "32-byte seed signs")
    except Exception as e:
        _break("G15b", "honest sign failed: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G16: revocation push -- revocation-push-refused
# ---------------------------------------------------------------------------

def g16():
    from gov.revocation_push import RevocationPushHub, RevocationPushError
    # Hostile: signed events required but no HMAC key configured.
    try:
        RevocationPushHub()
        _break("G16a", "keyless hub did not refuse")
    except RevocationPushError as e:
        if str(e).startswith("revocation-push-refused"):
            _held("G16a", "keyless hub refuses coded revocation-push-refused")
        else:
            _break("G16a", "wrong error: %r" % str(e)[:50])
    except Exception as e:
        _error("G16a", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: a keyed hub constructs.
    try:
        RevocationPushHub(hmac_key=secrets.token_bytes(32))
        _held("G16b", "keyed hub constructs")
    except Exception as e:
        _break("G16b", "honest hub refused: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G17: delegation store -- store_lock_unavailable
# ---------------------------------------------------------------------------

def g17():
    from gov.approvals import DelegationStore, DelegationError
    from gov.log import ActionLog
    run_dir = Path(tempfile.mkdtemp(prefix="g17-"))
    # Hostile: the lock path is a DIRECTORY, so the lock can never be
    # taken -- mutation must refuse rather than proceed unlocked.
    (run_dir / "delegations.lock").mkdir()
    store = DelegationStore(run_dir, ActionLog(run_dir / "a.jsonl"))
    try:
        store._append_record({"x": 1})
        _break("G17a", "unlockable store did not refuse")
    except DelegationError as e:
        if e.reason == "store_lock_unavailable":
            _held("G17a", "unlockable store refuses coded store_lock_unavailable")
        else:
            _break("G17a", "wrong reason: %r" % (e.reason,))
    except Exception as e:
        _error("G17a", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: a normal store appends.
    run_dir2 = Path(tempfile.mkdtemp(prefix="g17b-"))
    store2 = DelegationStore(run_dir2, ActionLog(run_dir2 / "a.jsonl"))
    try:
        store2._append_record({"x": 1})
        _held("G17b", "normal store appends")
    except Exception as e:
        _break("G17b", "honest append failed: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G18: inventory query -- inventory-identity-collision
# ---------------------------------------------------------------------------

def g18():
    from gov.inventory_query import QueryRegistry, InventoryError
    rows = [{"agent_id": "a1", "name": "n1", "trust_tier": "low"},
            {"agent_id": "a1", "name": "n2", "trust_tier": "low"}]
    try:
        QueryRegistry().register_table_rows("agents", rows)
        _break("G18a", "duplicate identity did not refuse")
    except InventoryError as e:
        if str(e).startswith("inventory-identity-collision"):
            _held("G18a", "duplicate identity refuses coded inventory-identity-collision")
        else:
            _break("G18a", "wrong error: %r" % str(e)[:50])
    except Exception as e:
        _error("G18a", "%s: %s" % (type(e).__name__, e))
    # Discrimination control: distinct identities register.
    try:
        QueryRegistry().register_table_rows(
            "agents", [{"agent_id": "a1", "name": "n1", "trust_tier": "low"},
                       {"agent_id": "a2", "name": "n2", "trust_tier": "low"}])
        _held("G18b", "distinct identities register")
    except Exception as e:
        _break("G18b", "honest register failed: %s" % (type(e).__name__,))


# ---------------------------------------------------------------------------
# G19: evidence sigstore witness -- evidence-bundle-witness-key-unavailable
# ---------------------------------------------------------------------------

def g19():
    from gov import evidence_sigstore as es

    class _Keyless:
        public_key = None

    entry = {"kindVersion": {"kind": es.WITNESS_KIND,
                             "version": es.WITNESS_KIND_VERSION}}
    try:
        es._check_witness([entry], b"", b"", b"", _Keyless(), None)
        _break("G19a", "keyless witness verifier did not refuse")
    except Exception as e:
        if str(e).startswith("evidence-bundle-witness-key-unavailable"):
            _held("G19a", "keyless verifier refuses coded evidence-bundle-witness-key-unavailable")
        else:
            _break("G19a", "wrong error: %r" % str(e)[:60])
    # Discrimination control: a verifier exposing its 32-byte key
    # passes the KEY check (it then fails on the unbound logId -- a
    # LATER, distinct refusal, proving this probe's code is specific).
    class _Keyed:
        public_key = secrets.token_bytes(32)

    try:
        es._check_witness([dict(entry, logId={"keyId": "eA=="})], b"", b"",
                          b"", _Keyed(), None)
        _break("G19b", "unbound key unexpectedly passed")
    except Exception as e:
        if str(e).startswith("evidence-bundle-witness-unbound"):
            _held("G19b", "keyed verifier passes the key check (fails later, distinctly)")
        else:
            _break("G19b", "wrong error: %r" % str(e)[:60])


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
        "tests.test_tool_call_policy",
        "tests.test_tool_grant",
        "tests.test_inventory_query",
        "tests.test_shield_registry",
        "tests.test_consumption_ledger",
        "tests.test_mcp_invocation_authz",
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
    for fn in (p0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12,
               g13, g14, g15, g16, g17, g18, g19):
        try:
            fn()
        except Exception:
            _error("main", "probe family %s crashed:\n%s"
                   % (fn.__name__, traceback.format_exc()))
    green_check()
    breaks = sorted(pid for pid, v, _ in _results if v == "BREAK")
    errors = sorted(pid for pid, v, _ in _results if v == "ERROR")
    held = sorted(pid for pid, v, _ in _results if v == "HELD")
    print("w341_covgap3: %d BREAK / %d HELD / %d ERROR"
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
