#!/usr/bin/env python3
"""Exporter-narrowing adversarial battery (H20, wave-125 lane).

Spec section 7 / K-060 honest scope: an evidence bundle proves
authenticity of its *included* entries, not completeness against a
misbehaving exporter. The exporter holds the source log; it can drop
tail entries from the log before sealing, or narrow the sealed window
from the head, and the resulting bundle still verifies -- the
verifier has no external reference to the true log. The real fix is
an external anchor (H24, v2 decision); this battery pins the gap red.

Probe map:
  e1_full_log_verified: full synthetic log -> seal -> assemble ->
     verify_bundle -> VERIFIED (code 0). Control: the honest path
     verifies.
  e2_truncated_tail_still_verified: exporter drops the last 3 log
     entries (including a detector_trip escalation) from the source
     log file, then seals the truncated log -> VERIFIED (code 0).
     BREAK (pinned): the escalation vanished silently; the chain is
     internally consistent so nothing in the bundle betrays the
     omission. This is the K-060 residual.
  e3_narrowed_head_still_verified: exporter seals with
     window={"from_seq": 4, ...} (to_seq == tip, so the non-tip
     refusal does not fire) -> VERIFIED (code 0). BREAK (pinned):
     window_coverage honestly declares the narrowed window, but a
     verifier without the source log cannot tell head entries were
     omitted.
  e4_non_tip_window_refused: window with to_seq < tip -> build()
     raises EvidenceBundleError. HELD: the existing partial
     mitigation (non-tip refusal) holds.

Verdicts:
- HELD  = control behaved as claimed (e1 verified, e4 refused).
- BREAK = a narrowed/exporter-shaped bundle still verified (the
          K-060 residual, pinned -- NOT a new finding).
- ERROR = probe/instrumentation problem.

Honest ceiling: only an external transparency anchor (the bundle's
tip hash anchored outside the exporter's control) makes omission
detectable. That is H24, a v2 decision, correctly deferred.

All probes use real product code (no stubs). $0 spend,
synthetic/local. Deterministic: fixed Ed25519 key, fixed log
content; verdicts do not depend on wall-clock time.

Run:
  mkdir -p /tmp/gov-h20
  TMPDIR=/tmp/gov-h20 ~/workspace/.gov-venv/bin/python evals/evidence_bundle_exporter_narrow.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-h20b ~/workspace/.gov-venv/bin/python evals/evidence_bundle_exporter_narrow.py
"""

import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-h20")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.log import ActionLog  # noqa: E402
from gov.evidence_bundle import (  # noqa: E402
    EvidenceBundle, EvidenceBundleError, log_evidence_bundle_receipt)
from gov.evidence_verify import verify_bundle  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
from tests.keyfixture import provision_test_key  # noqa: E402

_UNGOVERNED_ACK = (
    "h20 exporter-narrowing eval: synthetic red-team harness; raw "
    "pre-wave-74/75 pipeline by design, declared and chained")

_SIGNER_BYTES = bytes.fromhex("a0" * 32)


def _append(log, event, **kw):
    kw.setdefault("agent_id", "a1")
    kw.setdefault("run_id", "r1")
    kw.setdefault("decision", "allow")
    kw.setdefault("policy_id", "p-default")
    kw["event"] = event
    return log.append(kw)


def _build_log(path, signer):
    """Deterministic synthetic log with a detector_trip near the tail."""
    log = ActionLog(path, signer=signer)
    _append(log, "policy_loaded", decision="policy_loaded",
            policy_id="policy-pin",
            policy_path="/etc/gov/policy.yaml", policy_hash="ab" * 32,
            pinned=True,
            reason="Policy loaded for run r1")
    _append(log, "tool_call", tool="read_file")
    _append(log, "tool_call", tool="http_post", decision="queued_pending",
            policy_id="p-critical", approval_id="A-1")
    _append(log, "approval_decision", agent_id="human",
            decision="approved", approval_id="A-1", policy_id="p-critical")
    # The entries the misbehaving exporter will drop in e2.
    _append(log, "detector_trip", agent_id="monitor", decision="escalated",
            signal="velocity_breaker", reason="bulk exfil tempo")
    _append(log, "tool_call", tool="http_post", decision="denied",
            policy_id="p-critical", reason="breaker tripped")
    return log


def _seal_and_verify(log_path, signer, window=None, out_name="b"):
    """Seal the log at log_path and verify the assembled bundle.

    Returns (verify_code, out_dir)."""
    eb = EvidenceBundle(log_path, window=window)
    payload = eb.build()
    manifest = eb.seal(payload, signer=signer)
    log_evidence_bundle_receipt(
        manifest, ActionLog(log_path, signer=signer), signer=signer)
    op = {"key_id": signer.key_id,
          "public_key_hex": signer.public_key.hex()}
    out = os.path.join(tempfile.mkdtemp(prefix="govh20-"), out_name)
    eb.assemble(payload, manifest, operator_key=op,
                checkpoint_keys=[dict(op)], out_dir=out)
    code, _checks, _summary = verify_bundle(
        out, pins=[signer.public_key.hex()])
    return code, out


def _fresh_run_dir():
    return Path(tempfile.mkdtemp(prefix="govh20-"))


def run_battery():
    provision_test_key(epoch="h20")
    results = []

    # e1: honest full-log path verifies.
    d1 = _fresh_run_dir()
    lp1 = str(d1 / "audit.log")
    s1 = Ed25519Signer(_SIGNER_BYTES)
    _build_log(lp1, s1)
    code1, _ = _seal_and_verify(lp1, s1, out_name="e1")
    results.append(("e1_full_log_verified",
                    "HELD" if code1 == 0 else "ERROR",
                    "full log sealed and verified (code=%s)" % code1))

    # e2: exporter truncates the tail (drops the detector_trip +
    # denial), then truncates the checkpoint sidecar to match. The
    # exporter holds the log key, so the rewritten sidecar is valid:
    # the checkpoint only stops a keyless attacker, not the
    # key-holding exporter (the K-060 threat model).
    d2 = _fresh_run_dir()
    lp2 = str(d2 / "audit.log")
    s2 = Ed25519Signer(_SIGNER_BYTES)
    _build_log(lp2, s2)
    with open(lp2, "r", encoding="utf-8") as f:
        lines = f.read().splitlines()
    # Drop the last 2 entries (detector_trip + denied post).
    keep = len(lines) - 2
    with open(lp2, "w", encoding="utf-8") as f:
        f.write("\n".join(lines[:keep]) + "\n")
    cp2 = d2 / "checkpoints.jsonl"
    if cp2.exists():
        cp_lines = cp2.read_text(encoding="utf-8").splitlines()
        cp2.write_text("\n".join(cp_lines[:keep]) + "\n",
                       encoding="utf-8")
    code2, _ = _seal_and_verify(lp2, s2, out_name="e2")
    results.append(("e2_truncated_tail_still_verified",
                    "BREAK" if code2 == 0 else
                    ("HELD" if code2 != 0 else "ERROR"),
                    "tail-truncated log sealed; verify code=%s "
                    "(K-060: omission invisible)" % code2))

    # e3: exporter narrows from the head (from_seq=4, to_seq=tip).
    d3 = _fresh_run_dir()
    lp3 = str(d3 / "audit.log")
    s3 = Ed25519Signer(_SIGNER_BYTES)
    _build_log(lp3, s3)
    from gov.log import read_entries
    tip_seq = read_entries(lp3)[-1]["seq"]
    code3, _ = _seal_and_verify(
        lp3, s3, window={"from_seq": 4, "to_seq": tip_seq}, out_name="e3")
    results.append(("e3_narrowed_head_still_verified",
                    "BREAK" if code3 == 0 else
                    ("HELD" if code3 != 0 else "ERROR"),
                    "head-narrowed window sealed; verify code=%s "
                    "(K-060: head omission silent)" % code3))

    # e4: non-tip window is refused (existing partial mitigation).
    d4 = _fresh_run_dir()
    lp4 = str(d4 / "audit.log")
    s4 = Ed25519Signer(_SIGNER_BYTES)
    _build_log(lp4, s4)
    tip_seq4 = read_entries(lp4)[-1]["seq"]
    try:
        EvidenceBundle(
            lp4, window={"from_seq": 1,
                        "to_seq": tip_seq4 - 1}).build()
        results.append(("e4_non_tip_window_refused", "ERROR",
                        "non-tip window was NOT refused"))
    except EvidenceBundleError as e:
        results.append(("e4_non_tip_window_refused", "HELD",
                        "non-tip window refused: %s" % str(e)[:80]))

    return results


def main():
    # Deterministic: run twice, verdicts must agree.
    r1 = run_battery()
    r2 = run_battery()
    det = [a[1] for a in r1] == [a[1] for a in r2]
    n_break = sum(1 for _, v, _ in r1 if v == "BREAK")
    n_held = sum(1 for _, v, _ in r1 if v == "HELD")
    n_err = sum(1 for _, v, _ in r1 if v == "ERROR")
    print("H20 EXPORTER-NARROWING battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)" % (n_break, n_held, n_err,
                                                 det))
    for name, verdict, detail in r1:
        print("  %-32s %-5s %s" % (name, verdict, detail))
    print("NOTE: BREAKs are the PINNED K-060 residual (bundle proves "
          "authenticity of included entries, not completeness against a "
          "misbehaving exporter), not new findings. Honest ceiling: "
          "external transparency anchor (H24, v2).")
    return 0 if n_err == 0 and det else 1


if __name__ == "__main__":
    sys.exit(main())
