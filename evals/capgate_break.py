#!/usr/bin/env python3
"""Stream-1 break-first battery: the capability gate wired to the runtime.

The capability harness grades governance (sealed SUFFICIENT/INSUFFICIENT
assessments) but no production runtime path consults the grade before
running agents. Each situation below is an attack against that gap:

  s1  run an agent with NO capability assessment on file
  s2a run on a STALE assessment (assessed against an older harness /
      thresholds config digest)
  s2b run on an EXPIRED assessment (older than the binding's freshness
      policy)
  s3  run on a FORGED SUFFICIENT assessment (genuine INSUFFICIENT seal,
      verdict flipped to SUFFICIENT, report digest recomputed -- the
      attacker cannot re-sign)
  s4  a governed-looking deployment (governed policy store + delegation
      context) with NO gate binding at all -- must be refused EXPLICITLY
      ("no capability gate configured ... configure or acknowledge"),
      never silently passed

Controls:

  s5  a valid, fresh, SUFFICIENT, authentically-sealed assessment lets
      the agent run (the gate is not "refuse everything")
  s6  an explicitly acknowledged ungoverned-capability deployment
      (capability_ungoverned_ack) constructs, chains its declaration,
      and runs -- declared, not silent

Verdicts:
- BREAK = the attack succeeds (agent runs / deployment constructs with
  no gate and no refusal)
- HELD  = the gate refuses (or the control behaves as specified)
- ERROR = probe/instrumentation problem, not a verdict

Pre-fix the tree has no gate seam: every attack situation scores BREAK
(the agent runs ungoverned) and the controls score trivially. Post-fix
the attacks must score HELD with zero battery edits -- the battery
detects the seam and switches to refusal assertions.

Deterministic across two runs. Synthetic/local only, no network.

Run: TMPDIR=/tmp/gov-capgate ~/workspace/.gov-venv/bin/python \
        evals/capgate_break.py
"""

import hashlib
import importlib.util
import inspect
import json
import os
import secrets
import sys
import tempfile
import time
import unittest  # noqa: F401  (kept for discoverability conventions)
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "capgate-break")
os.environ.setdefault("TMPDIR", "/tmp/gov-capgate")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import delegation_tokens as _dt  # noqa: E402
from gov import policy_change as _pc  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.safeguard_benchmark import DEFAULT_THRESHOLDS, SCHEMA_VERSION  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

HARNESS_ID = "gov.safeguard_benchmark.SafeguardAssessment"
_SID = "sess-capgate"
_REVOKE_URI = "https://revoke.example.invalid/deleg"
_BASE_POLICY = Path(REPO_ROOT, "policies", "default.yaml").read_text()

RESULTS = []


# ---------------------------------------------------------------------------
# Battery-local crypto/math (independent of gov/capability_gate.py, which
# may not exist yet: the battery must run red pre-fix). The seal math is
# the safeguard benchmark's: export_sha256 over the canonical report, and
# an Ed25519 seal over the canonical manifest minus the signing block.
# ---------------------------------------------------------------------------

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True,
                      separators=(",", ":")).encode("utf-8")


def _config_digest(thresholds):
    return hashlib.sha256(_canonical({
        "harness_id": HARNESS_ID,
        "schema_version": SCHEMA_VERSION,
        "thresholds": thresholds,
    })).hexdigest()


def _mint_assessment(report_verdict, thresholds, assessed_at, signer):
    report = {
        "report_id": {"value": "capgate-%s" % secrets.token_hex(4),
                      "provenance": {"kind": "battery"}},
        "sufficiency": {
            "aggregate_verdict": {
                "value": report_verdict,
                "provenance": {"kind": "battery"}},
            "verdict_reasons": {"value": [], "provenance": {"kind": "battery"}},
        },
    }
    manifest = {
        "kind": "capability_assessment_manifest",
        "generator": "evals/capgate_break.py",
        "harness_id": HARNESS_ID,
        "harness_config_digest": _config_digest(thresholds),
        "assessed_at": assessed_at,
        "report_id": report["report_id"]["value"],
        "export_sha256": hashlib.sha256(_canonical(report)).hexdigest(),
        "signing": None,
    }
    sign_bytes = _canonical({k: v for k, v in manifest.items()
                             if k != "signing"})
    manifest["signing"] = {
        "scheme": "ed25519",
        "key_id": signer.key_id,
        "signature_hex": signer.sign(sign_bytes).hex(),
    }
    return {"report": report, "manifest": manifest}


def _forge_sufficient(genuine):
    """Flip the verdict and recompute the report digest, exactly as an
    attacker holding the files (but not the seal key) would. The seal
    is copied unchanged -- it cannot be re-minted."""
    report = json.loads(json.dumps(genuine["report"]))
    report["sufficiency"]["aggregate_verdict"]["value"] = "SUFFICIENT"
    manifest = json.loads(json.dumps(genuine["manifest"]))
    manifest["report_id"] = report["report_id"]["value"]
    manifest["export_sha256"] = hashlib.sha256(
        _canonical(report)).hexdigest()
    return {"report": report, "manifest": manifest}


def _binding(signer, thresholds, freshness_seconds=3600):
    return {
        "harness_id": HARNESS_ID,
        "harness_digest": _config_digest(thresholds),
        "freshness_seconds": freshness_seconds,
        "trusted_keys": {signer.key_id: signer.public_key},
    }


# ---------------------------------------------------------------------------
# Governed-looking executor construction (real policy store, real bound
# delegation context, real chained log -- no mocks).
# ---------------------------------------------------------------------------

class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={"agent-1": self.parent[1]})


def _bound_ctx(keys, session):
    user_tok = _dt.issue_user_token(
        keys.idp[0], "user-7", ("tool:read_file", "tool:send_email"),
        session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "scout", "user-7",
        ("tool:read_file", "tool:send_email"), session, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file",), session, _REVOKE_URI, ttl_s=3600)
    ctx = _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=keys.trust(), session_id=session).bind()
    return ctx


def _governed_parts():
    run_dir = Path(tempfile.mkdtemp(prefix="govred-capgate-",
                                    dir=os.environ["TMPDIR"]))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    keys = _Keys()
    store = _pc.GovernedPolicyStore(deployment_mode="dev", trust=keys.trust(),
                                    log=log, session_id="sess-capgate")
    human = keys.human[0]
    store.bootstrap(_BASE_POLICY, human, "alice", "capgate genesis",
                    approver_signers=[human])
    engine = store.current_engine()
    # The delegation session is bound to the executor's run: the
    # delegation gate refuses cross-run token use.
    dctx = _bound_ctx(keys, session=run_dir.name)
    (run_dir / "notes.txt").write_text("capgate probe file\n")
    return {"run_dir": run_dir, "log": log, "approvals": approvals,
            "engine": engine, "store": store, "dctx": dctx}


def _executor(parts, **kw):
    return ToolExecutor(parts["run_dir"], parts["engine"], parts["log"],
                        parts["approvals"], policy_store=parts["store"],
                        delegation_context=parts["dctx"], **kw)


def _run_agent(parts, ex):
    ident = ex.mint_identity("agent-1", "scout", "user-7")
    return ex.call(ident, "read_file", path="notes.txt")


def _has_seam():
    """True once gov/capability_gate.py exists AND ToolExecutor accepts
    the declaration kwargs."""
    if importlib.util.find_spec("gov.capability_gate") is None:
        return False
    try:
        params = inspect.signature(ToolExecutor.__init__).parameters
    except (TypeError, ValueError):
        return False
    return "capability_gate_binding" in params


def _is_gate_refusal(exc, cause=None):
    if type(exc).__name__ != "CapabilityGateRefusal":
        return False
    if cause is None:
        return True
    return getattr(exc, "refusal_cause", None) == cause


# ---------------------------------------------------------------------------
# Situations
# ---------------------------------------------------------------------------

def s1_missing_assessment():
    """No capability assessment on file: the agent must not run."""
    if not _has_seam():
        p = _governed_parts()
        res = _run_agent(p, _executor(p))
        if res.get("status") == "executed":
            return ("BREAK", "no gate seam: agent ran with NO capability "
                             "assessment on file")
        return ("ERROR", "unexpected status=%r" % (res.get("status"),))
    signer = Ed25519Signer(secrets.token_bytes(32))
    p = _governed_parts()
    ex = _executor(p,
                   capability_gate_binding=_binding(signer,
                                                    DEFAULT_THRESHOLDS),
                   capability_assessment=None)
    try:
        _run_agent(p, ex)
    except Exception as e:  # noqa: BLE001 - verdict classification
        if _is_gate_refusal(e, "capability_assessment_missing"):
            return ("HELD", "refused: capability_assessment_missing")
        return ("ERROR", "%s: %s" % (type(e).__name__, e))
    return ("BREAK", "agent ran with no capability assessment")


def s2a_stale_harness_digest():
    """Assessment computed against an older harness/thresholds config:
    the binding pins the current digest, so the stale one must refuse."""
    if not _has_seam():
        p = _governed_parts()
        res = _run_agent(p, _executor(p))
        if res.get("status") == "executed":
            return ("BREAK", "no gate seam: agent ran; config-digest "
                             "staleness is unchecked")
        return ("ERROR", "unexpected status=%r" % (res.get("status"),))
    signer = Ed25519Signer(secrets.token_bytes(32))
    now = time.time()
    old_thresholds = dict(DEFAULT_THRESHOLDS, human_review_delta=999.0)
    stale = _mint_assessment("SUFFICIENT", old_thresholds, now, signer)
    p = _governed_parts()
    ex = _executor(p,
                   capability_gate_binding=_binding(signer,
                                                    DEFAULT_THRESHOLDS),
                   capability_assessment=stale)
    try:
        _run_agent(p, ex)
    except Exception as e:  # noqa: BLE001 - verdict classification
        if _is_gate_refusal(e, "harness_config_digest_mismatch"):
            return ("HELD", "refused: harness_config_digest_mismatch")
        return ("ERROR", "%s: %s" % (type(e).__name__, e))
    return ("BREAK", "agent ran on an assessment bound to a stale "
                     "harness config digest")


def s2b_expired_assessment():
    """Assessment older than the binding's freshness policy must refuse."""
    if not _has_seam():
        p = _governed_parts()
        res = _run_agent(p, _executor(p))
        if res.get("status") == "executed":
            return ("BREAK", "no gate seam: agent ran; assessment "
                             "freshness is unchecked")
        return ("ERROR", "unexpected status=%r" % (res.get("status"),))
    signer = Ed25519Signer(secrets.token_bytes(32))
    now = time.time()
    expired = _mint_assessment("SUFFICIENT", DEFAULT_THRESHOLDS,
                               now - 7200, signer)
    p = _governed_parts()
    ex = _executor(p,
                   capability_gate_binding=_binding(
                       signer, DEFAULT_THRESHOLDS, freshness_seconds=3600),
                   capability_assessment=expired)
    try:
        _run_agent(p, ex)
    except Exception as e:  # noqa: BLE001 - verdict classification
        if _is_gate_refusal(e, "capability_assessment_expired"):
            return ("HELD", "refused: capability_assessment_expired")
        return ("ERROR", "%s: %s" % (type(e).__name__, e))
    return ("BREAK", "agent ran on an expired capability assessment")


def s3_forged_sufficient():
    """Genuine INSUFFICIENT seal, verdict flipped to SUFFICIENT, report
    digest recomputed -- the seal cannot be re-minted, so the forgery
    must be refused."""
    if not _has_seam():
        p = _governed_parts()
        res = _run_agent(p, _executor(p))
        if res.get("status") == "executed":
            return ("BREAK", "no gate seam: agent ran; assessment "
                             "authenticity is unchecked")
        return ("ERROR", "unexpected status=%r" % (res.get("status"),))
    signer = Ed25519Signer(secrets.token_bytes(32))
    now = time.time()
    genuine = _mint_assessment("INSUFFICIENT", DEFAULT_THRESHOLDS,
                               now, signer)
    forged = _forge_sufficient(genuine)
    assert forged["report"]["sufficiency"]["aggregate_verdict"]["value"] \
        == "SUFFICIENT"
    assert forged["manifest"]["export_sha256"] == hashlib.sha256(
        _canonical(forged["report"])).hexdigest()
    p = _governed_parts()
    ex = _executor(p,
                   capability_gate_binding=_binding(signer,
                                                    DEFAULT_THRESHOLDS),
                   capability_assessment=forged)
    try:
        _run_agent(p, ex)
    except Exception as e:  # noqa: BLE001 - verdict classification
        if _is_gate_refusal(e, "assessment_signature_invalid"):
            return ("HELD", "refused: assessment_signature_invalid "
                            "(flipped verdict + recomputed digest)")
        return ("ERROR", "%s: %s" % (type(e).__name__, e))
    return ("BREAK", "agent ran on a forged SUFFICIENT assessment")


def s4_no_binding_looks_governed():
    """Governed core installed, no gate binding, no ack: construction
    must fail closed with an EXPLICIT error naming both remedies --
    never a silent pass."""
    if not _has_seam():
        p = _governed_parts()
        ex = _executor(p)
        res = _run_agent(p, ex)
        if res.get("status") == "executed":
            return ("BREAK", "no gate seam: governed-looking deployment "
                             "constructs and runs with no capability gate "
                             "and no refusal")
        return ("ERROR", "unexpected status=%r" % (res.get("status"),))
    p = _governed_parts()
    try:
        _executor(p)
    except Exception as e:  # noqa: BLE001 - verdict classification
        name = type(e).__name__
        msg = str(e)
        if name == "CapabilityGateBindingError" \
                and "capability_gate_binding" in msg \
                and "capability_ungoverned_ack" in msg:
            return ("HELD", "explicit refusal: no capability gate "
                            "configured; both remedies named")
        return ("ERROR", "%s: %s" % (name, e))
    return ("BREAK", "governed-looking deployment constructed with no "
                     "capability gate binding and no refusal")


def s5_valid_assessment_runs():
    """CONTROL: a valid, fresh, SUFFICIENT, authentically-sealed
    assessment lets the agent run -- the gate is not 'refuse
    everything'."""
    p = _governed_parts()
    if not _has_seam():
        res = _run_agent(p, _executor(p))
        if res.get("status") == "executed":
            return ("HELD", "control holds trivially pre-fix: agent runs")
        return ("ERROR", "unexpected status=%r" % (res.get("status"),))
    signer = Ed25519Signer(secrets.token_bytes(32))
    now = time.time()
    good = _mint_assessment("SUFFICIENT", DEFAULT_THRESHOLDS, now, signer)
    ex = _executor(p,
                   capability_gate_binding=_binding(signer,
                                                    DEFAULT_THRESHOLDS),
                   capability_assessment=good)
    try:
        res = _run_agent(p, ex)
    except Exception as e:  # noqa: BLE001 - verdict classification
        return ("ERROR", "valid assessment refused: %s: %s"
                % (type(e).__name__, e))
    if res.get("status") == "executed":
        return ("HELD", "control: valid assessment, agent runs")
    return ("ERROR", "unexpected status=%r" % (res.get("status"),))


def s6_acknowledged_ungoverned():
    """CONTROL: explicit capability_ungoverned_ack constructs, chains
    its declaration loudly, and runs -- declared, not silent."""
    if not _has_seam():
        return ("BREAK", "no ack seam: capability-ungoverned mode cannot "
                         "be declared -- every unwired deployment is "
                         "silent")
    p = _governed_parts()
    try:
        ex = _executor(
            p, capability_ungoverned_ack=(
                "capgate battery control: deliberate ungoverned-"
                "capability run"))
    except Exception as e:  # noqa: BLE001 - verdict classification
        return ("ERROR", "ack refused: %s: %s" % (type(e).__name__, e))
    entries = read_entries(p["run_dir"] / "actions.jsonl")
    declared = [e for e in entries
                if e.get("event") == "capability_gate_ungoverned_declared"]
    if not declared:
        return ("ERROR", "ack accepted but no declaration chained")
    try:
        res = _run_agent(p, ex)
    except Exception as e:  # noqa: BLE001 - verdict classification
        return ("ERROR", "ack'd run refused: %s: %s"
                % (type(e).__name__, e))
    if res.get("status") == "executed":
        return ("HELD", "control: declared ungoverned, declaration "
                         "chained, agent runs")
    return ("ERROR", "unexpected status=%r" % (res.get("status"),))


PROBES = [s1_missing_assessment, s2a_stale_harness_digest, s2b_expired_assessment,
          s3_forged_sufficient, s4_no_binding_looks_governed,
          s5_valid_assessment_runs, s6_acknowledged_ungoverned]


def run_once():
    out = []
    for probe in PROBES:
        try:
            verdict, detail = probe()
            out.append((probe.__name__, verdict, detail))
        except Exception as e:  # noqa: BLE001 - probe must not die
            out.append((probe.__name__, "ERROR", "%s: %s"
                        % (type(e).__name__, e)))
    return out


def main():
    first = run_once()
    second = run_once()
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    n_break = sum(1 for _, v, _ in first if v == "BREAK")
    n_held = sum(1 for _, v, _ in first if v == "HELD")
    n_err = sum(1 for _, v, _ in first if v == "ERROR")
    print("capgate break-first battery: %d BREAK / %d HELD / %d ERROR "
          "(seam present: %s; deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, _has_seam(), det))
    for name, verdict, detail in first:
        print("  %-28s %-6s %s" % (name, verdict, detail))
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
