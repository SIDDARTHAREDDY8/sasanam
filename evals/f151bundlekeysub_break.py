"""F151 closure battery: §5 bundle trust anchors and authorship pinning.

Pre-fix, ``gov/safeguard_bundle.py`` claimed a third party verifies
"with zero out-of-band inputs -- the bundle directory is the entire
trust input": ``bundle_verify`` took the bundle directory as its SOLE
input with no expected-operator-key pinning, so a forger's self-sealed
bundle (own log, checkpoint keys, operator key, forged all-stopped
battery -> SUFFICIENT) verified indistinguishably from the operator's
genuine bundle (1 BREAK / 2 HELD / 0 ERROR).

Post-fix, ``bundle_verify`` accepts optional authorship pinning
(``expected_operator_key_id`` /
``expected_operator_public_key_hex`` / ``expected_checkpoint_key_ids``)
and runs the B6 ``authorship_pinning`` check: pinned mismatches fail
closed (fatal — §4 is skipped), unpinned verification is explicitly
marked self-consistency-only (``not_applicable``) with the required
out-of-band key binding named in the check detail.

Held = the forger's bundle is REJECTED under the pinned operator key
while the operator's bundle passes, and unpinned verification
explicitly flags self-consistency-only instead of silently claiming
authorship.
"""

import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import json
import secrets
import tempfile

_KEY_VARS = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")


def _provision_key():
    saved = {k: os.environ.get(k) for k in _KEY_VARS}
    os.environ["GOV_LOG_KEY"] = secrets.token_bytes(32).hex()
    os.environ["GOV_LOG_KEY_EPOCH"] = "f151"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    return saved


def _restore_key(saved):
    for k, v in saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v


def _write_battery(records):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(records, f)
    return path


def _append(log, event, **kw):
    rec = {"event": event}
    rec.update(kw)
    return log.append(rec)


def _signer():
    from gov.signing import Ed25519Signer
    return Ed25519Signer(secrets.token_bytes(32))


def _build_log(path, signer):
    from gov.log import ActionLog
    log = ActionLog(path, signer=signer)
    _append(log, "tool_call", tool="read_file", agent_id="a1",
            run_id="r1", decision="allow", policy_id="p-default")
    _append(log, "tool_call", tool="send_email", agent_id="a1",
            run_id="r1", decision="queued_pending",
            policy_id="p-critical", approval_id="A-1")
    _append(log, "approval_decision", agent_id="human", run_id="r1",
            decision="approved", approval_id="A-1",
            policy_id="p-critical")
    # Anchor event: without a cited log seq the seal carries no
    # inclusion bundles and §4 step 3 cannot pass (mirrors the
    # repo's own bundle-test fixture).
    _append(log, "detector_trip", agent_id="monitor", run_id="r1",
            decision="escalated", policy_id="detection-breaker",
            reason="velocity breaker tripped")
    return log


def _sealed_bundle(tmp, name, battery_records, thresholds=None):
    """Build a full §5 bundle: log -> SAR -> seal -> receipt -> bundle.

    Each bundle gets its own subdirectory: the checkpoint sidecar
    (checkpoints.jsonl) lives next to the log, so two logs in one
    directory corrupt each other's chain verification.

    Returns (bundle_dir, report, manifest, signer).
    """
    from gov.log import ActionLog
    from gov.safeguard_benchmark import (
        SafeguardAssessment, log_benchmark_receipt)
    from gov.safeguard_bundle import bundle_assemble
    signer = _signer()
    sub = os.path.join(tmp, name + ".d")
    os.makedirs(sub, exist_ok=True)
    log_path = os.path.join(sub, "audit.log")
    _build_log(log_path, signer)
    battery_path = _write_battery(battery_records)
    try:
        sa = SafeguardAssessment(log_path, battery_path,
                                 thresholds=thresholds)
        rep = sa.build()
        manifest = sa.seal(rep, signer=signer)
        log_benchmark_receipt(
            manifest, ActionLog(log_path, signer=signer))
        op = {"key_id": signer.key_id,
              "public_key_hex": signer.public_key.hex()}
        info = bundle_assemble(
            rep, manifest, operator_key=op,
            checkpoint_keys=[dict(op)],
            out_dir=os.path.join(sub, "bundle"))
        return info["bundle_dir"], rep, manifest, signer
    finally:
        os.unlink(battery_path)


def _verdict_of(report):
    return report["sufficiency"]["aggregate_verdict"]["value"]


def p1_key_substitution_forgery():
    """HELD if the forger's self-sealed bundle is rejected under a pinned
    operator key, and unpinned verification explicitly documents its
    self-consistency-only residual.

    Victor binds the operator's Ed25519 key out-of-band (published key
    directory / transparency log / authenticated channel) and passes
    it as expected_operator_key_id. Mallory's self-sealed SUFFICIENT
    bundle (her own keys, her own log) must fail the pinning check; the
    operator's INSUFFICIENT bundle must still pass. Unpinned, both
    bundles verify — but the B6 check is explicitly not_applicable and
    names the out-of-band binding requirement (not a silent claim).
    """
    from gov.safeguard_bundle import bundle_verify
    tmp = tempfile.mkdtemp(prefix="f151-")
    # Operator: honest battery, one S1 break -> INSUFFICIENT.
    op_dir, op_rep, _op_man, op_signer = _sealed_bundle(
        tmp, "operator",
        [{"id": "p1", "category": "prompt_injection",
          "verdict": "stopped"},
         {"id": "p2", "category": "sandbox_escape",
          "verdict": "break"}])
    # Mallory: forged all-stopped battery + weakened thresholds ->
    # SUFFICIENT, sealed under her own keys.
    from gov.safeguard_benchmark import DEFAULT_THRESHOLDS
    weak = dict(DEFAULT_THRESHOLDS)
    weak["uncovered_forces_insufficient"] = False
    mal_dir, mal_rep, _mal_man, mal_signer = _sealed_bundle(
        tmp, "mallory",
        [{"id": "p1", "category": "prompt_injection",
          "verdict": "stopped"},
         {"id": "p2", "category": "sandbox_escape",
          "verdict": "stopped"}],
        thresholds=weak)
    op_v, mal_v = _verdict_of(op_rep), _verdict_of(mal_rep)
    # Pinned: Victor's out-of-band operator key.
    out_op = bundle_verify(
        op_dir, expected_operator_key_id=op_signer.key_id)
    out_mal = bundle_verify(
        mal_dir, expected_operator_key_id=op_signer.key_id)
    # Unpinned: documented self-consistency-only behavior.
    out_mal_unpinned = bundle_verify(mal_dir)
    b6 = next((c for c in out_mal_unpinned["checks"]
               if c.get("step") == "B6"), None)
    unpinned_honest = (b6 is not None
                       and b6["status"] == "not_applicable"
                       and "out-of-band" in b6.get("detail", ""))
    detail = ("operator verdict=%s pinned passed=%s; mallory verdict=%s "
              "pinned passed=%s; unpinned mallory passed=%s B6 honest=%s; "
              "different_operator_keys=%s" % (
                  op_v, out_op["passed"], mal_v,
                  out_mal["passed"], out_mal_unpinned["passed"],
                  unpinned_honest,
                  op_signer.public_key != mal_signer.public_key))
    if (op_v == "INSUFFICIENT" and mal_v == "SUFFICIENT"
            and out_op["passed"] and not out_mal["passed"]
            and unpinned_honest):
        return ("HELD",
                "forger's self-sealed SUFFICIENT bundle rejected "
                "under the pinned operator key; unpinned verification "
                "explicitly flags self-consistency-only; " + detail)
    if out_mal["passed"]:
        return ("BREAK",
                "pinned forgery still verifies: "
                + detail + "; failures=%s" % (out_mal["failures"],))
    return ("ERROR", "unexpected: " + detail)


def p2_tamper_control():
    """CONTROL: flipping a verdict byte inside a genuine bundle fails."""
    from gov.safeguard_bundle import (
        bundle_verify, compute_bundle_digest, DIGEST_FILE)
    tmp = tempfile.mkdtemp(prefix="f151-")
    bdir, rep, _man, _signer = _sealed_bundle(
        tmp, "op2",
        [{"id": "p1", "category": "prompt_injection",
          "verdict": "stopped"},
         {"id": "p2", "category": "sandbox_escape",
          "verdict": "break"}])
    assert _verdict_of(rep) == "INSUFFICIENT"
    pre = bundle_verify(bdir)
    if not pre["passed"]:
        return ("ERROR",
                "pre-tamper bundle does not verify (vacuous "
                "control): %s" % (pre["failures"],))
    rp = os.path.join(bdir, "report.json")
    with open(rp, "rb") as f:
        raw = f.read()
    assert b"INSUFFICIENT" in raw
    with open(rp, "wb") as f:
        f.write(raw.replace(b"INSUFFICIENT", b"SUFFICIENT", 1))
    digest = compute_bundle_digest(bdir)
    with open(os.path.join(bdir, DIGEST_FILE), "w",
              encoding="utf-8") as f:
        f.write(digest + "\n")
    out = bundle_verify(bdir)
    if not out["passed"]:
        return ("HELD",
                "tampered genuine bundle rejected (crypto holds)")
    return ("ERROR", "tampered bundle verified: %s" % (out["failures"],))


def p3_honest_control():
    """CONTROL: the genuine operator bundle verifies."""
    from gov.safeguard_bundle import bundle_verify
    tmp = tempfile.mkdtemp(prefix="f151-")
    bdir, rep, _man, _signer = _sealed_bundle(
        tmp, "op3",
        [{"id": "p1", "category": "prompt_injection",
          "verdict": "stopped"}])
    out = bundle_verify(bdir)
    if out["passed"]:
        return ("HELD", "honest bundle verifies (verdict=%s)"
                % _verdict_of(rep))
    return ("ERROR", "honest bundle failed: %s" % (out["failures"],))


def p4_assembler_key_mismatch_footgun():
    """INFO: bundle_assemble does not bind the key envelope to the seal.

    Assembling the operator's sealed pair with a DIFFERENT operator
    key (not the sealing key) succeeds silently; only bundle_verify
    fails (at the §4 seal step). Fail-closed at verify, but the
    assembler will happily ship a bundle that can never verify.
    """
    from gov.log import ActionLog
    from gov.safeguard_benchmark import (
        SafeguardAssessment, log_benchmark_receipt)
    from gov.safeguard_bundle import bundle_assemble, bundle_verify
    tmp = tempfile.mkdtemp(prefix="f151-")
    signer = _signer()
    log_path = os.path.join(tmp, "a4.audit.log")
    _build_log(log_path, signer)
    battery_path = _write_battery(
        [{"id": "p1", "category": "prompt_injection",
          "verdict": "stopped"}])
    try:
        sa = SafeguardAssessment(log_path, battery_path)
        rep = sa.build()
        manifest = sa.seal(rep, signer=signer)
        log_benchmark_receipt(
            manifest, ActionLog(log_path, signer=signer))
    finally:
        os.unlink(battery_path)
    wrong = _signer()
    op = {"key_id": wrong.key_id,
          "public_key_hex": wrong.public_key.hex()}
    try:
        info = bundle_assemble(
            rep, manifest, operator_key=op,
            checkpoint_keys=[dict(op)],
            out_dir=os.path.join(tmp, "a4.bundle"))
    except Exception as e:
        return ("HELD",
                "assembler refused mismatched operator key: %s: %s"
                % (type(e).__name__, e))
    out = bundle_verify(info["bundle_dir"])
    seal_fails = any("step 5" in f for f in out["failures"])
    return ("INFO",
            "assembler shipped mismatched-key bundle silently; "
            "verify fails=%s (step5 seal fail=%s)"
            % (not out["passed"], seal_fails))


def main():
    saved = _provision_key()
    results = []
    try:
        for name, fn in [
                ("p1_key_substitution_forgery",
                 p1_key_substitution_forgery),
                ("p2_tamper_control", p2_tamper_control),
                ("p3_honest_control", p3_honest_control),
                ("p4_assembler_key_mismatch_footgun",
                 p4_assembler_key_mismatch_footgun)]:
            try:
                verdict, detail = fn()
            except Exception as e:  # noqa: BLE001 - battery never crashes
                verdict, detail = "ERROR", "%s: %s" % (
                    type(e).__name__, e)
            results.append((name, verdict, detail))
            print("  %-34s %-6s %s" % (name, verdict, detail))
    finally:
        _restore_key(saved)
    n_break = sum(1 for _, v, _ in results if v == "BREAK")
    n_held = sum(1 for _, v, _ in results if v == "HELD")
    n_err = sum(1 for _, v, _ in results if v == "ERROR")
    print("F151 candidate battery: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    return 1 if n_break else 0


if __name__ == "__main__":
    sys.exit(main())
