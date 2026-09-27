"""Row-12 wave-158: default-on deployment-manifest attachment probes.

RED-FIRST battery. The deployment-pinned artifact manifest (wave-152/153,
gov/artifact_inventory_manifest.py) was OPT-IN: a deployment that never
attached one ran with the artifact-integrity seam silently absent, and no
construction-time decision existed at all. This battery pins the closure:

  * staging: a manifest-capable deployment (every ToolExecutor
    construction) must EITHER attach the operator-pinned envelope OR
    record an explicit opt-out reason. Silent absence is LOUD -- a
    chained ``deployment_manifest_absent`` event -- never silent.
  * production: silent absence is fail-closed
    (DeploymentManifestRequiredError); only an attached envelope or a
    recorded opt-out lets construction proceed.
  * contradictory (envelope + opt-out) and hollow (blank) opt-outs are
    refused; forged/malformed envelopes fail loud at construction.
  * spawned children inherit the deployment's manifest posture.

Pre-seam every situation below is BREAK (the gap: no decision exists).
Post-seam the battery must read 0 BREAK in staging AND under a clean
environment, deterministic x2.

Out of scope by design (documented residuals, not regressions):
  * undeclared paths / content-shape exfiltration without file
    references (the manifest only constrains what it pins);
  * same-process compromised executor or compromised deployment
    key / dishonest ceremony (outside the tamper-evidence model).
"""

import contextlib
import io
import json
import os
import secrets
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "manifest-default-on")
# Wave-95 lesson: the harness's ungoverned_ack is refused in production,
# so the module default must be staging; production situations patch the
# env var around construction only.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("TMPDIR", "/tmp/gov-manifest-default-on")
Path(os.environ["TMPDIR"]).mkdir(parents=True, exist_ok=True)

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.log import read_entries  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov import artifact_inventory_manifest as _manifest_mod  # noqa: E402

try:
    # Post-seam: the default-on gate.
    from gov.executor import DeploymentManifestRequiredError  # noqa: E402
    from gov.executor import _deployment_manifest_construction_check  # noqa: E402
except ImportError:  # pre-seam: the gate does not exist yet
    DeploymentManifestRequiredError = None
    _deployment_manifest_construction_check = None

DEFAULT_POLICY = Path(REPO_ROOT) / "policies" / "default.yaml"

_UNGOVERNED_ACK = (
    "manifest-default-on eval: synthetic red-team harness; raw "
    "pre-wave-74/75 pipeline by design, declared and chained")

_OPT_OUT_REASON = "no deployment-critical files in this deployment"


# ---------------------------------------------------------------------------
# Session plumbing
# ---------------------------------------------------------------------------

def _session(**kw):
    """Staging executor on the raw pipeline (ungoverned_ack)."""
    run_dir = Path(tempfile.mkdtemp(prefix="govmanif-",
                                    dir=os.environ["TMPDIR"]))
    policy = PolicyEngine(str(DEFAULT_POLICY))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(run_dir, policy, log, approvals,
                      ledger_path=run_dir / "egress_ledger.jsonl",
                      ungoverned_ack=_UNGOVERNED_ACK, **kw)
    return {"run_dir": run_dir, "executor": ex, "log": log,
            "approvals": approvals}


def _governed_session(deployment_manifest=None,
                      deployment_manifest_opt_out=None,
                      mode="staging"):
    """Full executor with the governed core (policy_store +
    delegation_context), so production-mode construction is possible.
    Returns the session dict plus the test keys (needed for spawn)."""
    from gov import delegation_tokens as _dt
    from gov import policy_change as _pc
    from gov import capability_gate as _cg
    from gov.signing import Ed25519Signer

    old_mode = os.environ.get("GOV_DEPLOYMENT_MODE")
    os.environ["GOV_DEPLOYMENT_MODE"] = mode
    try:
        run_dir = Path(tempfile.mkdtemp(prefix="govmanif-gov-",
                                        dir=os.environ["TMPDIR"]))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        human = _dt.generate_test_keypair()
        idp = _dt.generate_test_keypair()
        authority = _dt.generate_test_keypair()
        parent = _dt.generate_test_keypair()
        trust = _dt.DelegationTrust(
            human_keys={human[0].key_id: human[1]},
            authority_keys={authority[0].key_id: authority[1]},
            user_issuer_keys={idp[0].key_id: idp[1]},
            agent_keys={"agent-1": parent[1]})
        store = _pc.GovernedPolicyStore(
            deployment_mode="dev", trust=trust, log=log,
            session_id="sess-manifest-default-on")
        base_policy = (Path(REPO_ROOT) / "policies"
                       / "default.yaml").read_text(encoding="utf-8")
        store.bootstrap(base_policy, human[0], "alice",
                        "manifest-default-on test genesis",
                        approver_signers=[human[0]])
        engine = store.current_engine()
        session_id = run_dir.name
        scopes = ("tool:read_file", "tool:write_file")
        user_tok = _dt.issue_user_token(idp[0], "user-7", scopes,
                                        session_id, ttl_s=3600)
        agent_tok = _dt.issue_agent_token(authority[0], "agent-1", "coder",
                                          "user-7", scopes, session_id,
                                          ttl_s=3600)
        deleg_tok = _dt.issue_delegation(
            human[0], "user-7", user_tok, agent_tok, scopes, session_id,
            "https://revoke.example.invalid/deleg", ttl_s=3600)
        dctx = _dt.DelegationContext(
            parent_chain=[], trust=trust, session_id=session_id,
            **{"user_token": user_tok, "agent_token": agent_tok,
               "delegation_token": deleg_tok}).bind()
        cap_kw = {}
        if mode == "production":
            # Production refuses capability_ungoverned_ack: bind a real
            # (test) capability gate.
            signer = Ed25519Signer(secrets.token_bytes(32))
            digest = _cg.compute_harness_digest("gov.manifest.harness",
                                                {"a": 1}, "v1")
            cap_kw["capability_gate_binding"] = {
                "harness_id": "gov.manifest.harness",
                "harness_digest": digest,
                "freshness_seconds": 3600,
                "trusted_keys": {signer.key_id: signer.public_key},
            }
        else:
            cap_kw["capability_ungoverned_ack"] = (
                "manifest-default-on eval: staging governed run, "
                "capability gate ungoverned by declaration")
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            # Manifest kwargs are passed only when set: pre-seam the
            # executor has no such parameters (TypeError would mask the
            # honest pre-seam gap demonstration in p1).
            manifest_kw = {}
            if deployment_manifest is not None:
                manifest_kw["deployment_manifest"] = deployment_manifest
            if deployment_manifest_opt_out is not None:
                manifest_kw["deployment_manifest_opt_out"] = (
                    deployment_manifest_opt_out)
            ex = ToolExecutor(
                run_dir, engine, log, approvals,
                ledger_path=run_dir / "egress_ledger.jsonl",
                policy_store=store, delegation_context=dctx,
                **manifest_kw,
                **cap_kw)
        return {"run_dir": run_dir, "executor": ex, "log": log,
                "approvals": approvals, "parent_signer": parent[0]}
    finally:
        if old_mode is None:
            os.environ.pop("GOV_DEPLOYMENT_MODE", None)
        else:
            os.environ["GOV_DEPLOYMENT_MODE"] = old_mode


def _events(ctx, name):
    return [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
            if isinstance(e, dict) and e.get("event") == name]


def _seam_present():
    return DeploymentManifestRequiredError is not None


# ---------------------------------------------------------------------------
# Staging situations: silent absence must be LOUD, never silent
# ---------------------------------------------------------------------------

def s1_staging_silent_is_loud():
    """Staging, no envelope, no opt-out: construction proceeds (staging
    is not production) BUT the absence is chained LOUD as
    deployment_manifest_absent. Pre-seam: no event, no decision -- the
    gap is silence itself."""
    ctx = _session()
    ex = ctx["executor"]
    if getattr(ex, "_deployment_manifest_decision", None) != "absent":
        return ("BREAK", "no manifest decision recorded at construction "
                "(decision=%r) -- the absence is silent"
                % (getattr(ex, "_deployment_manifest_decision", None),))
    evs = _events(ctx, "deployment_manifest_absent")
    if len(evs) != 1:
        return ("BREAK", "expected exactly one deployment_manifest_absent "
                "event, got %d" % len(evs))
    if evs[0].get("deployment_mode") != "staging":
        return ("ERROR", "absent event has wrong mode: %r"
                % (evs[0].get("deployment_mode"),))
    return ("HELD", "silent absence is LOUD in staging: chained "
            "deployment_manifest_absent (decision=absent)")


def s2_staging_envelope_attached():
    """Staging + operator-pinned envelope: attached, verified, chained."""
    if not _seam_present():
        return ("BREAK", "pre-seam: deployment_manifest kwarg does not "
                "exist -- the envelope cannot be attached at construction")
    try:
        env = _manifest_mod.pin_manifest({"a.bin": "ab" * 32})
        ctx = _session(deployment_manifest=env)
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    ex = ctx["executor"]
    if getattr(ex, "_deployment_manifest_decision", None) != "attached":
        return ("BREAK", "decision != 'attached': %r"
                % (getattr(ex, "_deployment_manifest_decision", None),))
    if not ex.artifacts.has_deployment_manifest:
        return ("BREAK", "envelope was not attached to the inventory")
    evs = _events(ctx, "deployment_manifest_attached")
    if len(evs) != 1:
        return ("BREAK", "expected one deployment_manifest_attached "
                "event, got %d" % len(evs))
    ev = evs[0]
    if ev.get("manifest_digest") != _manifest_mod.manifest_digest(env):
        return ("BREAK", "attached event carries wrong manifest_digest")
    if ev.get("entry_count") != 1 or not ev.get("key_epoch"):
        return ("BREAK", "attached event missing entry_count/key_epoch")
    return ("HELD", "envelope attached + verified + chained "
            "(digest=%s...)" % ev["manifest_digest"][:16])


def s3_staging_optout_recorded():
    """Staging + explicit opt-out reason: recorded, chained, proceeds."""
    if not _seam_present():
        return ("BREAK", "pre-seam: deployment_manifest_opt_out kwarg "
                "does not exist")
    try:
        ctx = _session(deployment_manifest_opt_out=_OPT_OUT_REASON)
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    ex = ctx["executor"]
    if getattr(ex, "_deployment_manifest_decision", None) != "opt_out":
        return ("BREAK", "decision != 'opt_out': %r"
                % (getattr(ex, "_deployment_manifest_decision", None),))
    evs = _events(ctx, "deployment_manifest_opt_out")
    if len(evs) != 1:
        return ("BREAK", "expected one deployment_manifest_opt_out "
                "event, got %d" % len(evs))
    if evs[0].get("opt_out_reason") != _OPT_OUT_REASON:
        return ("BREAK", "opt-out event does not carry the reason")
    if ex.artifacts.has_deployment_manifest:
        return ("BREAK", "opt-out run should not have a manifest")
    return ("HELD", "explicit opt-out recorded and chained "
            "(reason=%r)" % _OPT_OUT_REASON)


def s4_contradiction_refused():
    """Envelope AND opt-out together: contradictory, refused."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no contradiction check exists")
    env = _manifest_mod.pin_manifest({"a.bin": "ab" * 32})
    try:
        _session(deployment_manifest=env,
                 deployment_manifest_opt_out=_OPT_OUT_REASON)
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    except DeploymentManifestRequiredError:
        return ("HELD", "contradictory envelope+opt-out refused "
                "fail-closed")
    return ("BREAK", "contradictory envelope+opt-out was accepted")


def s5_blank_optout_refused():
    """Blank / whitespace-only opt-out: hollow justification (F131),
    refused."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no opt-out validation exists")
    for bad in ("", "   ", "\t\n"):
        try:
            _session(deployment_manifest_opt_out=bad)
        except TypeError as exc:
            return ("BREAK", "pre-seam: %s" % (exc,))
        except DeploymentManifestRequiredError:
            continue
        return ("BREAK", "blank opt-out %r was accepted" % (bad,))
    # Non-string opt-out is also hollow.
    try:
        _session(deployment_manifest_opt_out=12345)
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    except DeploymentManifestRequiredError:
        return ("HELD", "blank/whitespace/non-string opt-outs refused "
                "(F131 hollow justification)")
    return ("BREAK", "non-string opt-out was accepted")


def s6_forged_envelope_fail_loud():
    """Tampered pin: fail LOUD at construction, never a silent gap."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no envelope verification at "
                "construction")
    env = _manifest_mod.pin_manifest({"a.bin": "ab" * 32})
    env["pin"] = "00" * 32
    try:
        _session(deployment_manifest=env)
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    except ValueError:
        return ("HELD", "forged envelope refused fail-loud at "
                "construction (ValueError)")
    return ("BREAK", "forged envelope was attached without complaint")


def s7_pinstripped_envelope_fail_loud():
    """Pin-stripped envelope: fail LOUD at construction."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no envelope verification at "
                "construction")
    env = _manifest_mod.pin_manifest({"a.bin": "ab" * 32})
    del env["pin"]
    try:
        _session(deployment_manifest=env)
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    except ValueError:
        return ("HELD", "pin-stripped envelope refused fail-loud at "
                "construction (ValueError)")
    return ("BREAK", "pin-stripped envelope was attached without complaint")


# ---------------------------------------------------------------------------
# Spawn inheritance (staging, governed core for the delegation plumbing)
# ---------------------------------------------------------------------------

def s8_spawn_inherits_envelope():
    """A spawned child inherits the deployment's envelope; the shared
    inventory keeps the manifest (one run, one inventory)."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no manifest posture to inherit")
    env = _manifest_mod.pin_manifest({"a.bin": "ab" * 32})
    try:
        ctx = _governed_session(deployment_manifest=env, mode="staging")
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    ex = ctx["executor"]
    try:
        child = ex.spawn_sub_agent("child-1", ("tool:read_file",),
                                   ctx["parent_signer"])
    except Exception as exc:
        return ("ERROR", "spawn failed: %r" % (exc,))
    if getattr(child, "_deployment_manifest_decision", None) != "attached":
        return ("BREAK", "child decision != 'attached': %r"
                % (getattr(child, "_deployment_manifest_decision", None),))
    if child.artifacts is not ex.artifacts:
        return ("BREAK", "child does not share the parent's inventory")
    if not child.artifacts.has_deployment_manifest:
        return ("BREAK", "shared inventory lost the manifest at spawn")
    return ("HELD", "child inherits the envelope; one run, one "
            "manifest-bearing inventory")


def s9_spawn_inherits_optout():
    """A spawned child inherits the recorded opt-out (not a fresh
    silent absence)."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no manifest posture to inherit")
    try:
        ctx = _governed_session(
            deployment_manifest_opt_out=_OPT_OUT_REASON, mode="staging")
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    ex = ctx["executor"]
    try:
        child = ex.spawn_sub_agent("child-1", ("tool:read_file",),
                                   ctx["parent_signer"])
    except Exception as exc:
        return ("ERROR", "spawn failed: %r" % (exc,))
    if getattr(child, "_deployment_manifest_decision", None) != "opt_out":
        return ("BREAK", "child decision != 'opt_out': %r"
                % (getattr(child, "_deployment_manifest_decision", None),))
    evs = [e for e in read_entries(ctx["run_dir"] / "actions.jsonl")
           if isinstance(e, dict)
           and e.get("event") == "deployment_manifest_opt_out"]
    if len(evs) != 2:  # parent + child, loud by design
        return ("BREAK", "expected parent+child opt-out events, got %d"
                % len(evs))
    return ("HELD", "child inherits the recorded opt-out (2 chained "
            "declarations, loud by design)")


def s10_unknown_mode_fails_closed():
    """Unresolvable deployment mode fails closed TOWARD refusal, never
    silently toward 'no guard' (wave-85 idiom). Unit-level: the full
    constructor cannot reach the manifest gate under an unknown mode
    (the capability gate refuses first -- correct layering)."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no manifest gate exists")
    from gov import artifacts as _artifacts_mod
    inv = _artifacts_mod.ArtifactInventory()
    appended = []
    old_mode = os.environ.get("GOV_DEPLOYMENT_MODE")
    os.environ["GOV_DEPLOYMENT_MODE"] = "bogus-mode"
    try:
        _deployment_manifest_construction_check(
            "run-s10", appended.append, inv, None, None)
    except DeploymentManifestRequiredError:
        return ("HELD", "unknown mode failed closed toward refusal")
    except Exception as exc:
        return ("ERROR", "wrong exception: %r" % (exc,))
    finally:
        if old_mode is None:
            os.environ.pop("GOV_DEPLOYMENT_MODE", None)
        else:
            os.environ["GOV_DEPLOYMENT_MODE"] = old_mode
    return ("BREAK", "unknown mode did not fail closed")


# ---------------------------------------------------------------------------
# Production situations: silent absence is fail-closed
# ---------------------------------------------------------------------------

def p1_production_silent_refused():
    """Production, no envelope, no opt-out: construction REFUSED, with a
    chained deployment_manifest_refused record. Pre-seam this is THE
    gap: production construction succeeds with the seam silently
    absent."""
    if not _seam_present():
        # Pre-seam: demonstrate the actual gap -- production
        # construction succeeds silently.
        ctx = _governed_session(mode="production")
        ex = ctx["executor"]
        if getattr(ex, "_deployment_manifest_decision", None) is None:
            return ("BREAK", "GAP: production executor constructed with "
                    "no manifest, no opt-out, and no decision -- the "
                    "artifact-integrity seam is silently absent")
        return ("ERROR", "pre-seam unexpected decision: %r"
                % (getattr(ex, "_deployment_manifest_decision", None),))
    try:
        _governed_session(mode="production")
    except DeploymentManifestRequiredError:
        # Post-seam: the chained deployment_manifest_refused record is
        # pinned separately by p1b (the session dict is lost when the
        # constructor raises).
        return ("HELD", "production silent construction refused "
                "fail-closed (DeploymentManifestRequiredError)")
    return ("BREAK", "production silent construction was not refused")


def p1b_production_refusal_chained():
    """The production refusal leaves a chained deployment_manifest_refused
    record (the attempt itself is evidence)."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no refusal record exists")
    old_mode = os.environ.get("GOV_DEPLOYMENT_MODE")
    os.environ["GOV_DEPLOYMENT_MODE"] = "production"
    try:
        run_dir = Path(tempfile.mkdtemp(prefix="govmanif-p1b-",
                                        dir=os.environ["TMPDIR"]))
        log = ActionLog(run_dir / "actions.jsonl")
        # Direct gate call with a real chained log (no full executor
        # needed: the refusal path is what we are pinning).
        from gov import artifacts as _artifacts_mod
        inv = _artifacts_mod.ArtifactInventory()
        try:
            _deployment_manifest_construction_check(
                run_dir.name, log.append, inv, None, None)
        except DeploymentManifestRequiredError:
            pass
        else:
            return ("BREAK", "production silent check did not refuse")
        evs = [e for e in read_entries(run_dir / "actions.jsonl")
               if isinstance(e, dict)
               and e.get("event") == "deployment_manifest_refused"]
        if len(evs) != 1:
            return ("BREAK", "expected one deployment_manifest_refused "
                    "record, got %d" % len(evs))
        return ("HELD", "production refusal chained "
                "deployment_manifest_refused")
    finally:
        if old_mode is None:
            os.environ.pop("GOV_DEPLOYMENT_MODE", None)
        else:
            os.environ["GOV_DEPLOYMENT_MODE"] = old_mode


def p2_production_optout_ok():
    """Production + recorded opt-out: construction proceeds."""
    if not _seam_present():
        return ("BREAK", "pre-seam: deployment_manifest_opt_out kwarg "
                "does not exist")
    try:
        ctx = _governed_session(
            deployment_manifest_opt_out=_OPT_OUT_REASON, mode="production")
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    ex = ctx["executor"]
    if getattr(ex, "_deployment_manifest_decision", None) != "opt_out":
        return ("BREAK", "decision != 'opt_out': %r"
                % (getattr(ex, "_deployment_manifest_decision", None),))
    evs = _events(ctx, "deployment_manifest_opt_out")
    if len(evs) != 1 or evs[0].get("opt_out_reason") != _OPT_OUT_REASON:
        return ("BREAK", "opt-out not chained with the reason")
    return ("HELD", "production proceeds under a recorded opt-out")


def p3_production_envelope_ok():
    """Production + operator-pinned envelope: construction proceeds,
    manifest attached."""
    if not _seam_present():
        return ("BREAK", "pre-seam: deployment_manifest kwarg does not "
                "exist")
    env = _manifest_mod.pin_manifest({"a.bin": "ab" * 32})
    try:
        ctx = _governed_session(deployment_manifest=env, mode="production")
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    ex = ctx["executor"]
    if getattr(ex, "_deployment_manifest_decision", None) != "attached":
        return ("BREAK", "decision != 'attached': %r"
                % (getattr(ex, "_deployment_manifest_decision", None),))
    if not ex.artifacts.has_deployment_manifest:
        return ("BREAK", "envelope not attached in production")
    return ("HELD", "production proceeds with the envelope attached")


def p4_production_blank_optout_refused():
    """Production + blank opt-out: refused (no hollow bypass where the
    stakes are real)."""
    if not _seam_present():
        return ("BREAK", "pre-seam: no opt-out validation exists")
    try:
        _governed_session(deployment_manifest_opt_out="   ",
                          mode="production")
    except TypeError as exc:
        return ("BREAK", "pre-seam: %s" % (exc,))
    except DeploymentManifestRequiredError:
        return ("HELD", "production blank opt-out refused")
    return ("BREAK", "production blank opt-out was accepted")


PROBES = [
    ("s1_staging_silent_is_loud", s1_staging_silent_is_loud),
    ("s2_staging_envelope_attached", s2_staging_envelope_attached),
    ("s3_staging_optout_recorded", s3_staging_optout_recorded),
    ("s4_contradiction_refused", s4_contradiction_refused),
    ("s5_blank_optout_refused", s5_blank_optout_refused),
    ("s6_forged_envelope_fail_loud", s6_forged_envelope_fail_loud),
    ("s7_pinstripped_envelope_fail_loud", s7_pinstripped_envelope_fail_loud),
    ("s8_spawn_inherits_envelope", s8_spawn_inherits_envelope),
    ("s9_spawn_inherits_optout", s9_spawn_inherits_optout),
    ("s10_unknown_mode_fails_closed", s10_unknown_mode_fails_closed),
    ("p1_production_silent_refused", p1_production_silent_refused),
    ("p1b_production_refusal_chained", p1b_production_refusal_chained),
    ("p2_production_optout_ok", p2_production_optout_ok),
    ("p3_production_envelope_ok", p3_production_envelope_ok),
    ("p4_production_blank_optout_refused", p4_production_blank_optout_refused),
]


def main():
    held = brek = err = exp = 0
    print("manifest-default-on probes "
          "(%s)" % ("post-seam" if _seam_present() else "PRE-SEAM",))
    for name, fn in PROBES:
        try:
            verdict, detail = fn()
        except Exception as exc:  # noqa: BLE001 - battery must not crash
            verdict, detail = ("ERROR", "probe raised %r" % (exc,))
        print("%-36s %-8s %s" % (name, verdict, detail))
        if verdict == "HELD":
            held += 1
        elif verdict == "BREAK":
            brek += 1
        elif verdict == "EXPECTED":
            exp += 1
        else:
            err += 1
    print("result: %d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brek, exp, err))
    return 1 if (brek or err) else 0


if __name__ == "__main__":
    sys.exit(main())
