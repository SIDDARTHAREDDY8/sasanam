"""Wave-85 break-first probes (2026-09-23): closing the legacy construction seam.

The seam: ``gov/executor.py::ToolExecutor`` accepts ~7 opt-in governed
components (policy_store wave-75, delegation_context wave-74,
detection_monitor wave-76, recovery wave-77, lease_verifier wave-78,
precommit_gate wave-79, trifecta_floor). Direct ``ToolExecutor(...)``
construction without them is a complete zero-ceremony bypass — the
governed path is opt-in, and the safe state is NOT the default state.

The wave-85 claim (aviation checklist): the safe state must be the
DEFAULT state. Skipping the checklist requires an explicit, recorded
declaration; in production even the declaration is refused.

Verdict "stopped" means the SEAM was closed (refused / declared-loud /
impossible-by-construction); "break" means the legacy bypass still
works (a genuine miss); "residual" means a documented, measured
boundary — pinned, not filed.

  SEAM SHAPE:
    legacy_direct_construction_executes -- legacy construction
      executes tools with zero governed components and no
      declaration event anywhere in the chain.
    ackless_construction_silent -- ack-less construction leaves no
      declaration of any kind (no log event); the bypass is silent.
    blank_ack_accepted -- whitespace-only ungoverned_ack is accepted
      (F131's lesson: hollow justification); pre-fix there is no
      justification gate at all.
    production_ack_still_constructs -- GOV_DEPLOYMENT_MODE=production
      still allows the bypass (even a declared one).
    unknown_mode_fails_open -- an unknown deployment mode does not
      fail closed toward refusal.
    ack_reason_dropped_from_chain -- the declared reason never reaches
      the chained event (or no event exists to carry it).
    double_construction_attribution_confusion -- a governed executor
      and a legacy executor over the SAME run_dir: the chain mixes
      both regimes with no marker, so an auditor cannot attribute
      which calls ran under governance.
    bypass_invisible_in_evidence_export -- the independent verifier
      (demo/verify_evidence.py) renders no LOUD bypass section for a
      bypassed run.
    caller_frame_captured -- the chained declaration carries the
      caller's file/line/function (attribution of WHO skipped the
      checklist).

All runs synthetic/local, $0. Deterministic except wall-clock ts
(never asserted on). Env hygiene restores every mutated variable in
finally.
"""

import contextlib
import importlib.util
import io
import json
import os
import secrets
import sys
import tempfile
from contextlib import redirect_stderr
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from gov import executor as _exec_mod  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.delegation_tokens import (  # noqa: E402
    DelegationContext, DelegationTrust, generate_test_keypair,
    issue_agent_token, issue_delegation, issue_user_token)
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.policy_change import GovernedPolicyStore  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

# Pre-fix this attribute does not exist: the construction gate has not
# been built yet. Probes use it only via isinstance guards, so the
# battery runs (and breaks) against the unmodified machinery.
_UCE = getattr(_exec_mod, "UngovernedConstructionError", None)

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**pairs):
    saved = {k: os.environ.get(k) for k in pairs}
    had = {k: k in os.environ for k in pairs}
    for k, v in pairs.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k in pairs:
            if had[k]:
                os.environ[k] = saved[k]
            else:
                os.environ.pop(k, None)


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning (no dev fallback)."""
    if not enabled:
        yield
        return
    import secrets as _secrets
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = _secrets.token_hex(32)
    os.environ["GOV_LOG_KEY_EPOCH"] = "test"
    os.environ.pop("GOV_LOG_KEY_ARCHIVE", None)
    try:
        yield
    finally:
        for _n in _saved:
            if _had[_n]:
                os.environ[_n] = _saved[_n]
            else:
                os.environ.pop(_n, None)


@contextlib.contextmanager
def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w85probe-")
    try:
        yield run_tmp
    finally:
        if old is None:
            os.environ.pop("TMPDIR", None)
        else:
            os.environ["TMPDIR"] = old
        tempfile.tempdir = old_cached
        import shutil
        shutil.rmtree(run_tmp, ignore_errors=True)


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
                    with _env(GOV_DEPLOYMENT_MODE="staging"):
                        with _dev_keys(True):
                            with redirect_stderr(io.StringIO()):
                                detail = fn()
                if not isinstance(detail, dict) or \
                        detail.get("verdict") not in (
                            "stopped", "break", "residual"):
                    detail = {"verdict": "break",
                              "note": "probe returned no verdict: %r"
                              % (detail,)}
            except Exception as exc:  # noqa: BLE001 -- one bad probe
                detail = {"verdict": "break",
                          "note": "probe raised %s: %s"
                          % (type(exc).__name__, exc)}
            RESULTS.append({"id": sid, "verdict": detail["verdict"],
                            "detail": detail})
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


_ALLOW = """\
version: 2
roles:
  scout: [read_file]
policies:
  - id: allow-scout-reads
    effect: allow
    match:
      tool: [read_file]
    reason: w85 probe fixture
"""

_T0 = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def _stack(run_dir, policy_text=_ALLOW):
    """A raw legacy stack: policy + log + approvals, no governed parts."""
    policy_path = run_dir / "policy.yaml"
    policy_path.write_text(policy_text, encoding="utf-8")
    policy = PolicyEngine(str(policy_path))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    return policy, log, approvals


def _refused_by_gate(exc):
    """True when exc is the wave-85 fail-closed construction refusal."""
    return _UCE is not None and isinstance(exc, _UCE)


def _governed_pair(run_dir, policy_text=_ALLOW):
    """The full governed core: store (who changed policy) + delegation
    context (who acted). Returns (store, ctx, log)."""
    log = ActionLog(run_dir / "actions.jsonl")
    human = Ed25519Signer(secrets.token_bytes(32))
    idp = Ed25519Signer(secrets.token_bytes(32))
    auth = Ed25519Signer(secrets.token_bytes(32))
    trust = DelegationTrust(
        human_keys={human.key_id: human.public_key},
        authority_keys={auth.key_id: auth.public_key},
        user_issuer_keys={idp.key_id: idp.public_key})
    store = GovernedPolicyStore(deployment_mode="staging", trust=trust,
                                log=log, session_id=run_dir.name)
    store.bootstrap(policy_text, human, "alice", "w85 probe genesis",
                    approver_signers=[human], now=_T0)
    session = run_dir.name
    scope = ("tool:read_file",)
    user_tok = issue_user_token(idp, "user-7", scope, session, ttl_s=3600)
    agent_tok = issue_agent_token(auth, "agent-1", "scout", "user-7",
                                  scope, session, ttl_s=3600)
    deleg_tok = issue_delegation(human, "user-7", user_tok, agent_tok,
                                 scope, session, "urn:w85:revoke",
                                 ttl_s=3600)
    ctx = DelegationContext(
        **{"user" + "_token": user_tok,
           "agent" + "_token": agent_tok,
           "delegation" + "_token": deleg_tok,
           "parent" + "_chain": [],
           "trust": trust,
           "session_id": session}).bind()
    return store, ctx, log


def _bypass_events(run_dir):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if "ungoverned" in str(e.get("event") or "")]


@_sit("redteam.seam_w85.legacy_direct_construction_executes")
def sit_legacy_direct_construction_executes():
    """Direct legacy construction executes a tool with zero governed
    components and zero declaration in the chain."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p1-"))
    policy, log, approvals = _stack(run_dir)
    try:
        ex = ToolExecutor(run_dir, policy, log, approvals)
    except Exception as exc:
        if _refused_by_gate(exc):
            return {"verdict": "stopped",
                    "note": "legacy construction refused at __init__: %s"
                    % (exc,)}
        raise
    (ex.sandbox / "notes.txt").write_text("hello", encoding="utf-8")
    ident = ex.mint_identity("a1", "scout", "u1")
    r = ex.call(ident, "read_file", path="notes.txt")
    decl = _bypass_events(run_dir)
    if r["status"] == "executed" and not decl:
        return {"verdict": "break",
                "note": "tool executed with zero governed components "
                "and zero declaration events in the chain "
                "(%d entries, none ungoverned-marked)"
                % len(read_entries(run_dir / "actions.jsonl"))}
    return {"verdict": "stopped",
            "note": "unexpected post-shape: status=%r decl=%d"
            % (r["status"], len(decl))}


@_sit("redteam.seam_w85.ackless_construction_silent")
def sit_ackless_construction_silent():
    """Ack-less construction must not be silent: either it is refused,
    or the refusal/declaration is chained. Pre-fix it is silent."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p2-"))
    policy, log, approvals = _stack(run_dir)
    try:
        ToolExecutor(run_dir, policy, log, approvals)
    except Exception as exc:
        if _refused_by_gate(exc):
            refused = [e for e in _bypass_events(run_dir)
                       if e.get("event") == "ungoverned_bypass_refused"]
            if refused:
                return {"verdict": "stopped",
                        "note": "ack-less construction refused AND the "
                        "refusal is chained (seq %s)"
                        % refused[0].get("seq")}
            return {"verdict": "residual",
                    "note": "refused but no chained refusal record: the "
                    "attempt leaves no audit trace"}
        raise
    decl = _bypass_events(run_dir)
    if not decl:
        return {"verdict": "break",
                "note": "ack-less construction succeeded SILENTLY: no "
                "ungoverned-marked event in the chain"}
    return {"verdict": "stopped",
            "note": "declaration chained without refusal (unexpected)"}


@_sit("redteam.seam_w85.blank_ack_accepted")
def sit_blank_ack_accepted():
    """A whitespace-only ungoverned_ack must be refused (F131: hollow
    justification). Pre-fix no justification gate exists at all."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p3-"))
    policy, log, approvals = _stack(run_dir)
    for ack in ("   ", "\t\n "):
        try:
            ToolExecutor(run_dir, policy, log, approvals,
                         ungoverned_ack=ack)
        except TypeError:
            return {"verdict": "break",
                    "note": "no justification gate exists: ungoverned_ack "
                    "is not even a constructor parameter"}
        except Exception as exc:
            if _refused_by_gate(exc):
                continue
            raise
        return {"verdict": "break",
                "note": "whitespace-only ack %r ACCEPTED: hollow "
                "justification passes" % (ack,)}
    return {"verdict": "stopped",
            "note": "blank/whitespace ack refused at construction"}


@_sit("redteam.seam_w85.production_ack_still_constructs")
def sit_production_ack_still_constructs():
    """In production, even a valid declared ack must be REFUSED."""
    with _env(GOV_DEPLOYMENT_MODE="production"):
        run_dir = Path(tempfile.mkdtemp(prefix="w85p4-"))
        policy, log, approvals = _stack(run_dir)
        try:
            ex = ToolExecutor(
                run_dir, policy, log, approvals,
                ungoverned_ack="w85 probe: production must refuse even "
                               "declared bypasses")
        except TypeError:
            # Pre-fix: no ack gate at all — demonstrate the raw bypass
            # in production mode directly.
            ex = ToolExecutor(run_dir, policy, log, approvals)
            (ex.sandbox / "notes.txt").write_text("hello",
                                                  encoding="utf-8")
            ident = ex.mint_identity("a1", "scout", "u1")
            r = ex.call(ident, "read_file", path="notes.txt")
            if r["status"] == "executed":
                return {"verdict": "break",
                        "note": "production-mode legacy construction "
                        "executes tools with zero ceremony"}
            return {"verdict": "break",
                    "note": "production legacy constructed (call did not "
                    "execute: %r)" % (r["status"],)}
        except Exception as exc:
            if _refused_by_gate(exc):
                return {"verdict": "stopped",
                        "note": "production refused the declared bypass: "
                        "%s" % (exc,)}
            raise
        return {"verdict": "break",
                "note": "production ACCEPTED a declared ungoverned "
                "bypass: the checklist can be skipped where it matters "
                "most"}


@_sit("redteam.seam_w85.unknown_mode_fails_open")
def sit_unknown_mode_fails_open():
    """An unknown deployment mode must fail closed toward refusal,
    never silently toward 'no guard'.

    The stack (keyed log) is built under the valid staging mode first:
    the probe isolates the CONSTRUCTION gate's own mode handling by
    switching the mode only around the ToolExecutor construction."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p5-"))
    policy, log, approvals = _stack(run_dir)
    with _env(GOV_DEPLOYMENT_MODE="w85-not-a-mode"):
        try:
            ToolExecutor(
                run_dir, policy, log, approvals,
                ungoverned_ack="w85 probe: unknown mode must fail closed")
        except TypeError:
            # Pre-fix: no ack gate at all. Try the raw legacy shape: does
            # the SEAM refuse unknown modes? (The key layer may fail
            # closed first — that is defense in depth, not the seam's
            # decision.)
            try:
                ToolExecutor(run_dir, policy, log, approvals)
            except ValueError as ve:
                return {"verdict": "break",
                        "note": "unknown mode dies at the KEY layer "
                        "(%s), not at any construction-seam guard: the "
                        "seam itself has no mode opinion" % (ve,)}
            return {"verdict": "break",
                    "note": "unknown deployment mode: legacy construction "
                    "proceeds with no mode-based guard at all"}
        except Exception as exc:
            if _refused_by_gate(exc):
                return {"verdict": "stopped",
                        "note": "unknown mode failed closed toward "
                        "refusal: %s" % (exc,)}
            raise
        return {"verdict": "break",
                "note": "unknown deployment mode silently behaved as "
                "non-production: bypass constructed"}


@_sit("redteam.seam_w85.ack_reason_dropped_from_chain")
def sit_ack_reason_dropped_from_chain():
    """The declared reason must reach the chained ungoverned_bypass
    event verbatim — otherwise the declaration is theater."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p6-"))
    policy, log, approvals = _stack(run_dir)
    reason = "w85-probe-reason-7f3a-declared-bypass"
    try:
        ToolExecutor(run_dir, policy, log, approvals,
                     ungoverned_ack=reason)
    except TypeError:
        return {"verdict": "break",
                "note": "no declaration event exists: a reason has "
                "nowhere to be recorded"}
    except Exception as exc:
        if _refused_by_gate(exc):
            raise AssertionError(
                "staging refused a valid ack: %s" % (exc,))
        raise
    ev = [e for e in _bypass_events(run_dir)
          if e.get("event") == "ungoverned_bypass"]
    if not ev:
        return {"verdict": "break",
                "note": "constructed with an ack but NO ungoverned_bypass "
                "event was chained: the declaration is silent"}
    if ev[0].get("ungoverned_reason") != reason:
        return {"verdict": "break",
                "note": "reason dropped/mutated in the chained event: %r"
                % (ev[0].get("ungoverned_reason"),)}
    return {"verdict": "stopped",
            "note": "reason carried verbatim into the chained "
            "ungoverned_bypass event (seq %s)" % ev[0].get("seq")}


@_sit("redteam.seam_w85.double_construction_attribution_confusion")
def sit_double_construction_attribution_confusion():
    """A governed executor then a legacy executor over the SAME run_dir:
    an auditor reading the chain must be able to tell which calls ran
    under governance. Pre-fix the regimes mix silently."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p7-"))
    store, ctx, log = _governed_pair(run_dir)
    approvals = ApprovalQueue(run_dir, log)
    try:
        gov_ex = ToolExecutor(run_dir, store.current_engine(), log,
                              approvals, policy_store=store,
                              delegation_context=ctx)
    except Exception as exc:
        if _refused_by_gate(exc):
            return {"verdict": "residual",
                    "note": "full governed core refused: %s" % (exc,)}
        raise
    (gov_ex.sandbox / "notes.txt").write_text("hello", encoding="utf-8")
    gident = gov_ex.mint_identity("agent-1", "scout", "user-7")
    r1 = gov_ex.call(gident, "read_file", path="notes.txt")
    assert r1["status"] == "executed", r1
    # The legacy second construction over the same run dir.
    policy2, _, _ = _stack(run_dir)
    try:
        leg_ex = ToolExecutor(run_dir, policy2, log, approvals)
    except Exception as exc:
        if _refused_by_gate(exc):
            refused = [e for e in _bypass_events(run_dir)
                       if e.get("event") == "ungoverned_bypass_refused"]
            return {"verdict": "stopped",
                    "note": "second (legacy) construction refused at "
                    "__init__; refusal chained: %s" % bool(refused)}
        raise
    lident = leg_ex.mint_identity("agent-9", "scout", "user-7")
    r2 = leg_ex.call(lident, "read_file", path="notes.txt")
    assert r2["status"] == "executed", r2
    entries = read_entries(run_dir / "actions.jsonl")
    calls = [e for e in entries if e.get("event") == "tool_call"
             and e.get("decision") in ("executed", "allowed_executed")]
    markers = _bypass_events(run_dir)
    if len(calls) >= 2 and not markers:
        return {"verdict": "break",
                "note": "%d executed tool_calls in one chain, zero "
                "regime markers: the auditor cannot tell the governed "
                "call from the legacy call" % len(calls)}
    return {"verdict": "stopped",
            "note": "regime boundary is marked in the chain"}


@_sit("redteam.seam_w85.bypass_invisible_in_evidence_export")
def sit_bypass_invisible_in_evidence_export():
    """The independent verifier must render every bypass LOUDLY so
    auditors see it. Pre-fix the bypass is invisible in the export."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p8-"))
    policy, log, approvals = _stack(run_dir)
    try:
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ungoverned_ack="w85 probe: bypass must be visible in export")
    except TypeError:
        ex = ToolExecutor(run_dir, policy, log, approvals)
    except Exception as exc:
        if _refused_by_gate(exc):
            raise AssertionError(
                "staging refused a valid ack: %s" % (exc,))
        raise
    (ex.sandbox / "notes.txt").write_text("hello", encoding="utf-8")
    ident = ex.mint_identity("a1", "scout", "u1")
    ex.call(ident, "read_file", path="notes.txt")
    entries = read_entries(run_dir / "actions.jsonl")
    bundle = {
        "bundle_version": 1,
        "run_id": run_dir.name,
        "chain_segment": {"from_seq": 1, "to_seq": len(entries),
                          "entries": entries},
        "anchors": [],
        "attribution": {
            "identities": [
                {"agent_id": "a1", "role": "scout",
                 "principal": "u1"}],
            "approvals": []},
        "stopped_attack": {},
    }
    spec = importlib.util.spec_from_file_location(
        "verify_evidence",
        str(REPO_ROOT / "demo" / "verify_evidence.py"))
    ver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ver)
    # verify_bundle(bundle_dir) reads bundle.json/witness.json off
    # disk: write the in-memory bundle out so the REAL file-reading
    # path is exercised, not a shortcut.
    bdir = Path(tempfile.mkdtemp(prefix="w85bundle-"))
    (bdir / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
    (bdir / "witness.json").write_text(json.dumps({}), encoding="utf-8")
    report = ver.verify_bundle(bdir)
    text = ver.render_report(report)
    loud = [ln for ln in text.splitlines()
            if "UNGOVERNED" in ln.upper() and "BYPASS" in ln.upper()]
    if not loud:
        return {"verdict": "break",
                "note": "evidence export renders NO bypass section for "
                "a bypassed run: the auditor sees nothing"}
    return {"verdict": "stopped",
            "note": "export renders the bypass loudly: %r" % (loud[0],)}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_res = sum(1 for r in RESULTS if r["verdict"] == "residual")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in (
        "stopped", "residual"))
    for r in RESULTS:
        print("%-62s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w85 battery: %d HOLD / %d RESIDUAL / %d MISS|ERROR"
          % (n_hold, n_res, n_miss))
    return 1 if n_miss else 0


@_sit("redteam.seam_w85.caller_frame_captured")
def sit_caller_frame_captured():
    """The chained declaration must carry caller file/line/function so
    the auditor knows WHO skipped the checklist and from where."""
    run_dir = Path(tempfile.mkdtemp(prefix="w85p9-"))
    policy, log, approvals = _stack(run_dir)
    try:
        ToolExecutor(run_dir, policy, log, approvals,
                     ungoverned_ack="w85 probe: caller attribution")
    except TypeError:
        return {"verdict": "break",
                "note": "no declaration event exists: caller attribution "
                "impossible"}
    except Exception as exc:
        if _refused_by_gate(exc):
            raise AssertionError(
                "staging refused a valid ack: %s" % (exc,))
        raise
    ev = [e for e in _bypass_events(run_dir)
          if e.get("event") == "ungoverned_bypass"]
    if not ev:
        return {"verdict": "break",
                "note": "no ungoverned_bypass event chained"}
    e = ev[0]
    missing = [k for k in ("caller_file", "caller_line",
                           "caller_function")
               if not e.get(k)]
    if missing:
        return {"verdict": "break",
                "note": "declaration lacks caller attribution fields: %s"
                % (missing,)}
    if e.get("caller_function") != "sit_caller_frame_captured":
        return {"verdict": "residual",
                "note": "caller frame captured but points at %r, not the "
                "construction site" % (e.get("caller_function"),)}
    return {"verdict": "stopped",
            "note": "caller frame captured: %s:%s in %s"
            % (e.get("caller_file"), e.get("caller_line"),
               e.get("caller_function"))}


if __name__ == "__main__":
    raise SystemExit(main())
