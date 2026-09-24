"""Wave-86 break-first probes (2026-09-23): white-box adversarial battery
against the IDENTITY layer (gov/delegation_tokens.py — the three-token
identity + spawn lineage, wave-74).

White-box adversary: every probe is shaped from a reading of
``gov/delegation_tokens.py`` itself (the wave-84 anti-deception pattern
— assume the adversary READ THE MANUAL and engineers around it). The
battery runs break-first against the UNMODIFIED machinery; the pre-fix
headline is recorded before any fix lands.

Verdict "stopped" means the ATTACK was stopped (refused / detected /
impossible-by-construction); "break" means the identity layer failed to
catch it (a genuine miss — file-worthy); "residual" means a documented,
measured boundary — pinned, not filed.

Probe naming: redteam.identity_w86.<attack>.

  TOKEN INTEGRITY:
    token_forgery_resign_wrong_key -- valid delegation token re-signed
      with an attacker's key (same issuer claim; and issuer key_id
      rewritten to a rostered-but-wrong key): refused.
    token_claim_tamper_scope -- scope widened in claims, original sig
      kept: refused (the sig covers the canonical body).
    issuer_keyid_swap -- issuer names a rostered key, sig made by a
      different key: refused.
  CHAIN INTEGRITY:
    chain_splice_parent_swap -- depth-1 child re-pointed at a DIFFERENT
      valid parent: refused both when the tampered sig is presented and
      when the untampered child is presented with the wrong parent.
    chain_truncate_depth_lie -- depth-1 token presented with an empty
      parent_chain: refused (depth-vs-position mismatch).
    chain_reorder_hops -- ancestor order swapped (root-last): refused.
    parent_signature_key_swap -- child correctly parent-linked but signed
      by a key that is not the session-rostered parent key: refused.
    token_substitution_user_swap -- delegation bound to alice's user
      token presented with bob's user token: refused (South binding).
  ATTENUATION / DEPTH:
    spawn_widens_scope -- spawn with wider scope: refused at issuance AND
      a correctly parent-signed widened child refused at chain verify.
    depth_cap_evade -- chain past MAX_DELEGATION_DEPTH: refused at
      issuance (verify-side has no cap re-check — noted, not a miss).
  SESSION / TIME / DEPLOYMENT BINDING:
    expired_token_use -- token past expires_at + skew: refused at
      authorize time (bind-time validity does not linger).
    future_not_before_refused -- token whose not_before is in the
      future: refused.
    cross_session_replay -- session-X tokens presented in session Y:
      refused.
    cross_deployment_replay -- BREAK (expected pre-fix): tokens issued
      under deployment A's keys accepted by a verifier whose roster
      holds the SAME operator keys — the envelope carries no
      audience/deployment claim, so deployments are indistinguishable.
  CONTEXT DISCIPLINE:
    unbound_context_authorize -- authorize on a never-bound context:
      refused.
    sibling_context_borrow -- agent B calls enforce_tool_call with agent
      A's bound context: refused (subject mismatch).
    spawn_unbound_parent_refused -- spawn from an unbound parent:
      refused.
    missing_delegation_fails_closed -- enforce_tool_call with no context
      and bind with no delegation token: refused.
  LINEAGE VISIBILITY:
    spawn_lineage_invisible_to_log -- BREAK (expected pre-fix): a
      mid-run DelegationContext.spawn leaves NO chained record of the
      spawn (no parent ref, child ref, scope, or depth event) in the
      executor's audit log. The root's refs ARE stamped on call
      records (observability), but the spawn event itself is silent.
  REVOCATION SEAM:
    revocation_propagates_to_descendants -- revoked leaf refuses; a
      revoked PARENT invalidates the child's authorize: the seam
      propagates down the chain.

All runs synthetic/local, $0. Deterministic except key material and
wall-clock ts (never asserted on). Env hygiene restores every mutated
variable in finally. gov/ is NOT modified by this battery.
"""

import contextlib
import copy
import inspect
import io
import json
import os
import secrets
import sys
import tempfile
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Wave-100: the capability gate refuses declared-ungoverned construction
# in production. This battery is a test harness, not a deployment.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import gov.delegation_tokens as dt_mod  # noqa: E402
from gov import policy_change as pc_mod  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.delegation_tokens import (  # noqa: E402
    DelegationAttenuationError,
    DelegationBindingError,
    DelegationContext,
    DelegationError,
    DelegationExpiredError,
    DelegationRequiredError,
    DelegationSignatureError,
    DelegationTrust,
    authorize_action,
    enforce_tool_call,
    generate_test_keypair,
    issue_agent_token,
    issue_delegation,
    issue_user_token,
    token_ref,
    verify_delegation_chain,
)
from gov.executor import ToolExecutor, SpawnBudgetExhaustedError  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402
from gov.log import ActionLog  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _govrun():
    old = os.environ.get("TMPDIR")
    old_cached = tempfile.tempdir
    os.environ["TMPDIR"] = "/tmp/gov-run"
    tempfile.tempdir = None
    run_tmp = tempfile.mkdtemp(prefix="w86probe-")
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


@contextlib.contextmanager
def _dev_keys(enabled=True):
    """Wave-81: explicit test-key provisioning (no dev fallback)."""
    if not enabled:
        yield
        return
    _saved = {n: os.environ.get(n) for n in (
        "GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE")}
    _had = {n: n in os.environ for n in _saved}
    os.environ["GOV_LOG_KEY"] = secrets.token_hex(32)
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


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
                with _govrun():
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


_T0 = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)
_REVOKE = "https://revocation.synthetic.local/ep"
_AUDIT = ["https://audit.synthetic.local/log"]
_BASE = (REPO_ROOT / "policies" / "default.yaml").read_text()


def _keys():
    """Fresh four-role key material: human delegator, registration
    authority, IdP stand-in, and the agent's workload key."""
    human_s, human_p = generate_test_keypair()
    auth_s, auth_p = generate_test_keypair()
    idp_s, idp_p = generate_test_keypair()
    agent_s, agent_p = generate_test_keypair()
    return SimpleNamespace(human_s=human_s, human_p=human_p,
                           auth_s=auth_s, auth_p=auth_p,
                           idp_s=idp_s, idp_p=idp_p,
                           agent_s=agent_s, agent_p=agent_p)


def _trust_for(k, agent_id="agent-a", extra_humans=(),
               extra_agents=None, audience=None):
    humans = {k.human_s.key_id: k.human_p}
    for hs, hp in extra_humans:
        humans[hs.key_id] = hp
    agents = {agent_id: k.agent_p}
    agents.update(extra_agents or {})
    return DelegationTrust(
        human_keys=humans,
        authority_keys={k.auth_s.key_id: k.auth_p},
        user_issuer_keys={k.idp_s.key_id: k.idp_p},
        agent_keys=agents, audience=audience)


def _session(k=None, session_id="sess-w86-probe", user_id="alice",
             agent_id="agent-a", role="coder",
             user_perms=("tool:read_file", "tool:write_file"),
             agent_caps=("tool:*",),
             scope=("tool:read_file", "tool:write_file"),
             now=_T0, trust=None, audience=None):
    """A realistic session: roster, three tokens, BOUND context."""
    k = k or _keys()
    trust = trust if trust is not None else _trust_for(
        k, agent_id, audience=audience)
    utok = issue_user_token(k.idp_s, user_id, list(user_perms),
                            session_id, now=now, audience=audience)
    atok = issue_agent_token(k.auth_s, agent_id, role, user_id,
                             list(agent_caps), session_id, now=now,
                             audience=audience)
    dtok = issue_delegation(k.human_s, user_id, utok, atok,
                            list(scope), session_id, _REVOKE,
                            audit_urls=_AUDIT, now=now,
                            audience=audience)
    ctx = DelegationContext(user_token=utok, agent_token=atok,
                            delegation_token=dtok, parent_chain=[],
                            trust=trust,
                            session_id=session_id).bind(now=now)
    return SimpleNamespace(k=k, trust=trust, utok=utok, atok=atok,
                           dtok=dtok, ctx=ctx, session_id=session_id,
                           agent_id=agent_id, user_id=user_id)


def _resign(signer, token, **overrides):
    """White-box forgery helper: rebuild the token body (optionally
    with overridden fields) and sign it with the attacker's key."""
    body = {f: v for f, v in token.items() if f != "sig"}
    body.update(overrides)
    new = dict(body)
    new["sig"] = dt_mod._sign_body(signer, body)
    return new


def _child_claims(s, parent_tok, depth, scope, sub_id="agent-b",
                  delegator="agent-a"):
    return {
        "delegator": delegator,
        "user_token_hash": token_ref(s.utok),
        "agent_token_hash": token_ref(s.atok),
        "scope": list(scope),
        "revocation_endpoint": _REVOKE,
        "audit_urls": list(_AUDIT),
        "delegation_depth": depth,
        "parent_token_hash": token_ref(parent_tok),
    }


def _refused(fn, err=DelegationError):
    """Run fn; return (True, exc) if it raised the expected fail-closed
    error, else (False, result-or-wrong-exc)."""
    try:
        out = fn()
    except err as e:
        return True, e
    except Exception as e:  # noqa: BLE001
        return False, "wrong exception %s: %s" % (type(e).__name__, e)


def _audience_supported():
    """True when the envelope supports audience binding (the F132 fix)."""
    try:
        params = inspect.signature(
            DelegationTrust.__init__).parameters
        return "audience" in params
    except (TypeError, ValueError):  # noqa: BLE001
        return False
    return False, "NOT refused (returned %r)" % (out,)


# ----------------------------------------------------------------------
# The battery
# ----------------------------------------------------------------------

@_sit("redteam.identity_w86.token_forgery_resign_wrong_key")
def sit_token_forgery_resign_wrong_key():
    """White-box: the adversary read _sign_body/_verify_sig. Variant A:
    take a valid delegation token, re-sign its body with an ATTACKER's
    key while keeping the real issuer's key_id claim (signature must
    not verify against the rostered key). Variant B: re-sign with the
    attacker's key AND rewrite the issuer key_id to the attacker's
    (unknown to the roster). Both must be refused."""
    s = _session()
    atk_s, _atk_p = generate_test_keypair()
    forged_a = _resign(atk_s, s.dtok)  # issuer still names the human
    forged_b = _resign(atk_s, s.dtok, issuer=atk_s.key_id)
    for name, forged in (("A(same-issuer)", forged_a),
                         ("B(attacker-issuer)", forged_b)):
        ok, info = _refused(
            lambda f=forged: verify_delegation_chain(
                f, [], s.trust, s.utok, s.atok,
                expected_session=s.session_id, now=_T0),
            DelegationSignatureError)
        if not ok:
            return {"verdict": "break",
                    "note": "forged token variant %s accepted: %s"
                    % (name, info)}
    return {"verdict": "stopped",
            "note": "re-signed-with-attacker-key tokens refused on both "
                    "variants (issuer not in roster / signature invalid "
                    "against the rostered key)"}


@_sit("redteam.identity_w86.token_claim_tamper_scope")
def sit_token_claim_tamper_scope():
    """White-box: claims are just JSON under a detached sig — the
    obvious attack is widening scope in claims and keeping the valid
    original signature. The sig covers the canonical body, so the
    tamper must die at bind."""
    s = _session()
    tampered = copy.deepcopy(s.dtok)
    tampered["claims"]["scope"] = ["tool:*"]  # the widening
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=tampered, parent_chain=[],
            trust=s.trust, session_id=s.session_id).bind(now=_T0),
        DelegationSignatureError)
    if not ok:
        return {"verdict": "break",
                "note": "scope-widened token with original sig bound: %s"
                % (info,)}
    return {"verdict": "stopped",
            "note": "scope tamper refused: signature covers the "
                    "canonical claims (forgery, wrong key, or tampered "
                    "claims)"}


@_sit("redteam.identity_w86.chain_splice_parent_swap")
def sit_chain_splice_parent_swap():
    """White-box: the adversary holds a valid depth-1 child and a
    DIFFERENT valid depth-0 parent (both properly issued, same
    session). Attack A: rewrite the child's parent_token_hash to the
    other parent and present it with that parent (the sig dies).
    Attack B: present the UNTAMPERED child with the wrong parent (the
    parent-link check dies). Both refused."""
    s = _session()
    parent_b = issue_delegation(
        s.k.human_s, s.user_id, s.utok, s.atok, ["tool:read_file"],
        s.session_id, _REVOKE, audit_urls=_AUDIT, now=_T0)
    child = s.ctx.spawn("agent-b", ["tool:read_file"], s.k.agent_s,
                        now=_T0)
    tampered = copy.deepcopy(child.delegation_token)
    tampered["claims"]["parent_token_hash"] = token_ref(parent_b)
    ok_a, info_a = _refused(
        lambda: verify_delegation_chain(
            tampered, [parent_b], s.trust, s.utok, s.atok,
            expected_session=s.session_id, now=_T0),
        DelegationSignatureError)
    ok_b, info_b = _refused(
        lambda: verify_delegation_chain(
            child.delegation_token, [parent_b], s.trust, s.utok,
            s.atok, expected_session=s.session_id, now=_T0),
        DelegationSignatureError)
    if not (ok_a and ok_b):
        return {"verdict": "break",
                "note": "chain splice accepted: A(tampered-sig)=%s "
                        "B(wrong-parent)=%s" % (info_a, info_b)}
    return {"verdict": "stopped",
            "note": "parent swap refused both ways — the re-pointed "
                    "child dies on its signature, the untampered child "
                    "dies on the parent_token_hash link check"}


@_sit("redteam.identity_w86.chain_truncate_depth_lie")
def sit_chain_truncate_depth_lie():
    """White-box: parent_chain is caller-supplied, so the adversary
    presents a depth-1 child with an EMPTY parent_chain hoping the
    verifier treats it as a depth-0 root. The depth claim must be
    checked against chain position."""
    s = _session()
    child = s.ctx.spawn("agent-b", ["tool:read_file"], s.k.agent_s,
                        now=_T0)
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=child.delegation_token,
            parent_chain=[], trust=s.trust,
            session_id=s.session_id).bind(now=_T0),
        DelegationSignatureError)
    if not ok:
        return {"verdict": "break",
                "note": "truncated chain bound as root: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "depth-1 token with empty parent_chain refused "
                    "(hop 0 claims delegation_depth 1 — chain position "
                    "mismatch)"}


@_sit("redteam.identity_w86.chain_reorder_hops")
def sit_chain_reorder_hops():
    """White-box: ancestors are root-first by convention only. Present
    the chain root-LAST (child, then the real root) for a depth-2 leaf
    and see whether position-blind verification accepts it."""
    s = _session()
    child1 = s.ctx.spawn("sub-1", ["tool:read_file"], s.k.agent_s,
                         now=_T0)
    child2 = child1.spawn("sub-2", ["tool:read_file"], s.k.agent_s,
                          now=_T0)
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=child2.delegation_token,
            parent_chain=[child1.delegation_token, s.dtok],  # root-last
            trust=s.trust, session_id=s.session_id).bind(now=_T0),
        DelegationSignatureError)
    if not ok:
        return {"verdict": "break",
                "note": "reordered chain bound: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "root-last chain refused: hop 0 is not a depth-0 "
                    "token (wrong roster + depth/position mismatch)"}


@_sit("redteam.identity_w86.cross_deployment_replay")
def sit_cross_deployment_replay():
    """White-box: the token envelope has NO audience/deployment claim
    (checked below). Tokens issued under deployment A's keys are
    presented to a verifier whose roster holds the SAME
    human/authority/IdP keys (the shared-operator-key case) with the
    same session_id. If accepted, the deployment boundary is unenforced
    — the expected pre-fix break."""
    if _audience_supported():
        # POST-FIX CLOSURE SHAPE (F132): tokens bound to deployment A
        # must be refused by deployment B's verifier, even with shared
        # operator keys. Missing or mismatched aud -> DelegationBindingError.
        s = _session(session_id="sess-w86-shared", audience="deployment-a")
        k = s.k
        # Control passed already: _session() binds with the matching
        # deployment-a trust — we only reach this branch if that worked.
        trust_b = _trust_for(k, audience="deployment-b")
        ok, info = _refused(
            lambda: DelegationContext(
                user_token=s.utok, agent_token=s.atok,
                delegation_token=s.dtok, parent_chain=[],
                trust=trust_b, session_id=s.session_id).bind(now=_T0),
            DelegationBindingError)
        if not ok:
            return {"verdict": "break",
                    "note": "cross-deployment replay ACCEPTED by "
                            "deployment-B verifier despite aud "
                            "deployment-a: %s" % (info,)}
        # Missing-aud variant: aud-less tokens vs an audience-set
        # verifier must also die.
        s2 = _session(session_id="sess-w86-shared2")
        trust_a2 = _trust_for(s2.k, audience="deployment-a")
        ok2, info2 = _refused(
            lambda: DelegationContext(
                user_token=s2.utok, agent_token=s2.atok,
                delegation_token=s2.dtok, parent_chain=[],
                trust=trust_a2,
                session_id=s2.session_id).bind(now=_T0),
            DelegationBindingError)
        if not ok2:
            return {"verdict": "break",
                    "note": "aud-less tokens accepted by an "
                            "audience-configured verifier: %s" % (info2,)}
        return {"verdict": "stopped",
                "note": "F132 fixed: deployment-A tokens refused by the "
                        "deployment-B verifier (DelegationBindingError); "
                        "aud-less tokens refused when the verifier sets "
                        "an audience; own-deployment bind still works"}
    s = _session(session_id="sess-w86-shared")
    # Confirm the gap's premise: no audience/deployment claim anywhere.
    def _has_aud(obj):
        if isinstance(obj, dict):
            return any(k in ("audience", "aud", "deployment",
                             "deployment_id")
                       for k in obj) or any(_has_aud(v)
                                            for v in obj.values())
        if isinstance(obj, (list, tuple)):
            return any(_has_aud(v) for v in obj)
        return False
    if any(_has_aud(t) for t in (s.utok, s.atok, s.dtok)):
        return {"verdict": "stopped",
                "note": "envelope carries an audience/deployment claim "
                        "— premise of the probe is wrong"}
    # Deployment B: an independent roster object, same operator keys.
    k = s.k
    trust_b = DelegationTrust(
        human_keys={k.human_s.key_id: k.human_p},
        authority_keys={k.auth_s.key_id: k.auth_p},
        user_issuer_keys={k.idp_s.key_id: k.idp_p},
        agent_keys={s.agent_id: k.agent_p})
    try:
        ctx_b = DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=s.dtok, parent_chain=[],
            trust=trust_b, session_id=s.session_id).bind(now=_T0)
        verdict = authorize_action(ctx_b, "tool:read_file", now=_T0)
    except DelegationError as e:
        return {"verdict": "stopped",
                "note": "cross-deployment replay refused: %s: %s"
                % (type(e).__name__, e)}
    if not all(verdict["allowed_by"].values()):
        return {"verdict": "stopped",
                "note": "bound but the action was denied: %r"
                % (verdict["allowed_by"],)}
    return {"verdict": "break",
            "note": "cross-deployment replay ACCEPTED: deployment A's "
                    "tokens bound and authorized under deployment B's "
                    "roster (same operator keys, same session) — the "
                    "envelope has no audience/deployment claim, so the "
                    "verifier cannot tell deployments apart"}


@_sit("redteam.identity_w86.sibling_context_borrow")
def sit_sibling_context_borrow():
    """Regression pin (already in the code): agent B calls
    enforce_tool_call with agent A's BOUND context in the same run.
    The leaf delegation names its subject — the acting identity must
    match it."""
    s = _session()
    ident_a = AgentIdentity("agent-a", "coder", s.session_id, "alice")
    ident_b = AgentIdentity("agent-b", "coder", s.session_id, "alice")
    try:
        enforce_tool_call(s.ctx, ident_a, "read_file", now=_T0)
    except DelegationError as e:
        return {"verdict": "break",
                "note": "control failed: agent A's own call refused: "
                        "%s: %s" % (type(e).__name__, e)}
    ok, info = _refused(
        lambda: enforce_tool_call(s.ctx, ident_b, "read_file",
                                 now=_T0),
        DelegationBindingError)
    if not ok:
        return {"verdict": "break",
                "note": "sibling borrowed agent A's context: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "agent B's call with agent A's bound context "
                    "refused (acting identity != delegation subject); "
                    "agent A's own call passed the gate"}


@_sit("redteam.identity_w86.spawn_widens_scope")
def sit_spawn_widens_scope():
    """Regression pin (already in the code, both seams): spawn() with
    a scope entry outside the parent's must die at issuance, AND a
    correctly parent-SIGNED widened child must die at chain verify —
    the verifier re-checks attenuation, never trusts the issuer."""
    s = _session()  # parent scope: read_file + write_file
    ok_issue, info_issue = _refused(
        lambda: s.ctx.spawn("agent-b", ["tool:*"], s.k.agent_s,
                            now=_T0),
        DelegationAttenuationError)
    if not ok_issue:
        return {"verdict": "break",
                "note": "widening spawn issued: %s" % (info_issue,)}
    forged = dt_mod._base_token(
        "delegation", s.k.agent_s, "agent-b", s.session_id,
        _child_claims(s, s.dtok, 1,
                      ["tool:read_file", "tool:write_file",
                       "tool:send_email"]),
        None, _T0)
    ok_verify, info_verify = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=forged,
            parent_chain=[s.dtok], trust=s.trust,
            session_id=s.session_id).bind(now=_T0),
        DelegationAttenuationError)
    if not ok_verify:
        return {"verdict": "break",
                "note": "parent-signed widened child verified: %s"
                % (info_verify,)}
    return {"verdict": "stopped",
            "note": "scope widening refused at issuance (spawn) and at "
                    "chain verify (parent-signed widened child) — "
                    "attenuation is monotonic-decreasing on both seams"}


@_sit("redteam.identity_w86.spawn_lineage_invisible_to_log")
def sit_spawn_lineage_invisible_to_log():
    """Honest-recording probe: run a governed executor session (the
    realistic mid-run shape), spawn a sub-agent via
    DelegationContext.spawn, then inspect the executor's audit log for
    ANY chained record OF THE SPAWN — parent ref, child ref, scope, or
    depth. The root's refs ARE stamped on call records
    (identity_token_refs — observability works); the question is only
    whether the spawn event itself is recorded. Post-fix, the governed
    spawn mouth (ToolExecutor.spawn_sub_agent) chains the record — the
    probe closes over that path when it exists."""
    if hasattr(ToolExecutor, "spawn_sub_agent"):
        # POST-FIX CLOSURE SHAPE (F133): the governed spawn mouth must
        # chain an agent_spawn event with parent/child token refs,
        # scope, depth, and aud BEFORE returning; the child executor
        # must itself be governed.
        return _spawn_lineage_closure()
    run_dir = Path(tempfile.mkdtemp(prefix="w86spawn-"))
    lg = ActionLog(run_dir / "actions.jsonl")
    h1 = secrets.token_bytes(32)
    ph = Ed25519Signer(h1)
    pstore = pc_mod.GovernedPolicyStore(
        deployment_mode="dev",
        trust=DelegationTrust(
            human_keys={ph.key_id: ph.public_key},
            authority_keys={ph.key_id: ph.public_key},
            user_issuer_keys={ph.key_id: ph.public_key}),
        log=lg, session_id="w86-spawn-store")
    pstore.bootstrap(_BASE, ph, "alice", "init",
                     approver_signers=(ph,), now=_T0)
    sid = run_dir.name  # executor run_id == dir name; ctx must match
    # Wall-clock validity: the executor gate checks windows against real
    # now, so issue the delegation set for real now (not the fixed _T0).
    rt = datetime.now(timezone.utc)
    s = _session(session_id=sid, now=rt)
    ex = ToolExecutor(run_dir, pstore.current_engine(), lg,
                      ApprovalQueue(run_dir, lg),
                      policy_store=pstore,
                      delegation_context=s.ctx,
                      capability_ungoverned_ack=(
                          "w86 identity probes: subject under test is "
                          "delegation identity, not the capability "
                          "gate; declared, not silent"))
    ident = ex.mint_identity("agent-a", "coder", "alice")
    try:
        ex.call(ident, "read_file", path="notes.txt")
    except DelegationError as e:
        return {"verdict": "break",
                "note": "setup: the delegation gate refused the "
                        "legitimate call: %s: %s"
                        % (type(e).__name__, e)}
    # Mid-run spawn, then more legitimate activity as the parent.
    child = s.ctx.spawn("agent-b", ["tool:read_file"], s.k.agent_s,
                        now=rt)
    child_ref = token_ref(child.delegation_token)
    parent_ref = token_ref(s.dtok)
    try:
        ex.call(ident, "read_file", path="notes.txt")
    except DelegationError:
        pass
    entries = []
    for line in (run_dir / "actions.jsonl").read_text(
            encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    blob = json.dumps(entries)
    # A chained record OF THE SPAWN would be: an event whose NAME is
    # spawn-related, a prov record with a spawn/delegation_spawn
    # record_type, or any entry carrying the child's token ref. (Note:
    # the string "spawn" also appears in session ids like
    # "w86-spawn-store" — the match must be on event/record names, not
    # raw substrings.)
    spawn_events = []
    for e in entries:
        ev = e.get("event")
        if isinstance(ev, str) and "spawn" in ev.lower():
            spawn_events.append(e)
            continue
        prov = e.get("prov")
        if isinstance(prov, dict):
            rt_ = str(prov.get("record_type", "")).lower()
            if "spawn" in rt_ or "sub_agent" in rt_:
                spawn_events.append(e)
    child_mentioned = child_ref in blob
    parent_mentioned = parent_ref in blob
    if spawn_events or child_mentioned:
        return {"verdict": "stopped",
                "note": "the spawn left a chained record: events=%r "
                        "child_ref_in_log=%s" % (
                            [e.get("event") for e in spawn_events],
                            child_mentioned)}
    return {"verdict": "break",
            "note": "lineage gap: mid-run spawn() wrote NOTHING to the "
                    "executor's audit log — no spawn event, no child "
                    "ref %s..., no scope/depth record (parent ref "
                    "%s... IS stamped on call records via "
                    "identity_token_refs, so the root is observable but "
                    "the spawn itself is invisible)"
            % (child_ref[:12], parent_ref[:12])}


def _governed_executor_for_probe(prefix, audience=None, spawn_budget=None):
    """Build a governed executor (delegation + policy store + log) for
    the F133/GAP-2 closure probes. Returns
    (run_dir, log, executor, session, ledger)."""
    run_dir = Path(tempfile.mkdtemp(prefix=prefix))
    (run_dir / "notes.txt").write_text("hello", encoding="utf-8")
    lg = ActionLog(run_dir / "actions.jsonl")
    h1 = secrets.token_bytes(32)
    ph = Ed25519Signer(h1)
    pstore = pc_mod.GovernedPolicyStore(
        deployment_mode="dev",
        trust=DelegationTrust(
            human_keys={ph.key_id: ph.public_key},
            authority_keys={ph.key_id: ph.public_key},
            user_issuer_keys={ph.key_id: ph.public_key}),
        log=lg, session_id=prefix + "store")
    pstore.bootstrap(_BASE, ph, "alice", "init",
                     approver_signers=(ph,), now=_T0)
    sid = run_dir.name  # executor run_id == dir name; ctx must match
    rt = datetime.now(timezone.utc)  # wall-clock validity for the gate
    s = _session(session_id=sid, now=rt, audience=audience)
    ledger = dt_mod.RevocationLedger()
    ex = ToolExecutor(run_dir, pstore.current_engine(), lg,
                      ApprovalQueue(run_dir, lg),
                      policy_store=pstore,
                      delegation_context=s.ctx,
                      revocation_checker=ledger,
                      spawn_budget=spawn_budget,
                      # The capability gate is off-by-default and loud.
                      # These probes' subject is delegation identity /
                      # revocation / spawn budget, not the capability
                      # gate; declared, not silent.
                      capability_ungoverned_ack=(
                          "w86 identity probes: subject under test is "
                          "delegation identity, not the capability "
                          "gate; declared, not silent"),
                      session_identity=("agent-a", "coder", "alice"))
    return run_dir, lg, ex, s, ledger


def _spawn_lineage_closure():
    """Post-fix closure for the spawn-lineage gap (F133): the governed
    spawn mouth chains an agent_spawn event with parent/child refs,
    scope, depth, and aud BEFORE returning; the child executor is
    itself governed and inherits the revocation wiring."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        run_dir, _lg, ex, s, ledger = _governed_executor_for_probe(
            "w86spawnfix-")
        ident = ex._session_identity
        try:
            ex.call(ident, "read_file", path="notes.txt")
        except DelegationError as e:
            return {"verdict": "break",
                    "note": "setup: the delegation gate refused the "
                            "legitimate call: %s: %s"
                            % (type(e).__name__, e)}
        child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                      s.k.agent_s)
        entries = [json.loads(line)
                   for line in (run_dir / "actions.jsonl").read_text(
                       encoding="utf-8").splitlines()
                   if line.strip()]
        spawns = [e for e in entries
                  if e.get("event") == "agent_spawn"]
        if len(spawns) != 1:
            return {"verdict": "break",
                    "note": "governed spawn left %d agent_spawn events "
                            "(expected 1)" % len(spawns)}
        e = spawns[0]
        parent_ref = token_ref(s.dtok)
        child_ref = token_ref(
            child_ex._delegation_context.delegation_token)
        want = {"parent_token_ref": parent_ref,
                "child_token_ref": child_ref,
                "sub_agent_id": "agent-b",
                "sub_scope": ["tool:read_file"],
                "delegation_depth": 1,
                "delegator": "agent-a",
                "session_id": run_dir.name}
        bad = [k for k, v in want.items() if e.get(k) != v]
        if bad:
            return {"verdict": "break",
                    "note": "agent_spawn event has wrong fields: %s"
                    % (bad,)}
        # The child executor is itself governed: its provisioned
        # identity passes the real gate.
        if child_ex.run_id != ex.run_id:
            return {"verdict": "break",
                    "note": "child run_id %r != parent run_id %r — "
                            "session binding broken"
                            % (child_ex.run_id, ex.run_id)}
        try:
            res = child_ex.call(child_ex._session_identity, "read_file",
                                path="notes.txt")
        except DelegationError as e:
            return {"verdict": "break",
                    "note": "child executor call refused: %s: %s"
                            % (type(e).__name__, e)}
        if res["status"] != "executed":
            return {"verdict": "break",
                    "note": "child call not executed: %r" % (res,)}
        # The child inherits the revocation wiring.
        ledger.revoke(child_ex._delegation_context.delegation_token)
        ok, info = _refused(
            lambda: child_ex.call(child_ex._session_identity,
                                  "read_file", path="notes.txt"),
            dt_mod.DelegationRevokedError)
        if not ok:
            return {"verdict": "break",
                    "note": "revoked child token still authorizes on "
                            "the child executor: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "F133 fixed: governed spawn chained one agent_spawn "
                    "event with exact parent/child refs, scope, depth, "
                    "aud; the child executor is governed (real gate "
                    "passes) and inherits revocation wiring"}


@_sit("redteam.identity_w86.audience_missing_refused")
def sit_audience_missing_refused():
    """Closure pin (F132): aud-less tokens presented to an
    audience-configured verifier must die at bind — the audience check
    is not opt-out on the verifier side."""
    if not _audience_supported():
        return {"verdict": "break",
                "note": "no audience support in the envelope"}
    s = _session(session_id="sess-w86-noaud")
    trust_a = _trust_for(s.k, audience="deployment-a")
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=s.dtok, parent_chain=[],
            trust=trust_a, session_id=s.session_id).bind(now=_T0),
        DelegationBindingError)
    if not ok:
        return {"verdict": "break",
                "note": "aud-less tokens bound under an "
                        "audience-configured verifier: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "aud-less tokens refused by the audience-configured "
                    "verifier (DelegationBindingError)"}


@_sit("redteam.identity_w86.audience_spawn_inherits")
def sit_audience_spawn_inherits():
    """Closure pin (F132): spawn inherits aud from the parent token and
    exposes no audience parameter — a mid-run spawn cannot re-target a
    delegation at another deployment."""
    if not _audience_supported():
        return {"verdict": "break",
                "note": "no audience support in the envelope"}
    s = _session(session_id="sess-w86-audsp",
                 audience="deployment-a")
    child = s.ctx.spawn("agent-b", ["tool:read_file"], s.k.agent_s,
                        now=_T0)
    if child.delegation_token.get("aud") != "deployment-a":
        return {"verdict": "break",
                "note": "spawned child lost the aud claim: %r"
                        % (child.delegation_token.get("aud"),)}
    for mouth, sig in (
            ("DelegationContext.spawn",
             inspect.signature(DelegationContext.spawn)),
            ("ToolExecutor.spawn_sub_agent",
             inspect.signature(ToolExecutor.spawn_sub_agent))):
        if "audience" in sig.parameters:
            return {"verdict": "break",
                    "note": "%s takes an audience parameter — spawn-time "
                            "aud swapping is possible" % mouth}
    return {"verdict": "stopped",
            "note": "spawn inherited aud=deployment-a; neither spawn "
                    "mouth takes an audience parameter"}


@_sit("redteam.identity_w86.revocation_wired_at_executor_gate")
def sit_revocation_wired_at_executor_gate():
    """Closure pin (GAP 2): the executor's real tool-call path consults
    the revocation checker per call — leaf AND ancestors — and a
    raising checker fails closed as DelegationRevokedError, never a
    crash. The primitive-level check was never the question; the
    wiring was."""
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        run_dir, _lg, ex, s, ledger = _governed_executor_for_probe(
            "w86revoke-")
        ident = ex._session_identity
        try:
            res = ex.call(ident, "read_file", path="notes.txt")
        except DelegationError as e:
            return {"verdict": "break",
                    "note": "setup: legitimate call refused: %s: %s"
                            % (type(e).__name__, e)}
        if res["status"] != "executed":
            return {"verdict": "break",
                    "note": "setup: legitimate call not executed: %r"
                    % (res,)}
        # 1. Revoked LEAF: the very next call must die.
        ledger.revoke(s.dtok)
        ok, info = _refused(
            lambda: ex.call(ident, "read_file", path="notes.txt"),
            dt_mod.DelegationRevokedError)
        if not ok:
            return {"verdict": "break",
                    "note": "revoked leaf token still authorizes on the "
                            "executor path: %s" % (info,)}
        # 2. Revoked ANCESTOR: a child spawned before the parent's
        # revocation must die on its next call.
        run_dir2, _lg2, ex2, s2, ledger2 = _governed_executor_for_probe(
            "w86revoke2-")
        child_ex = ex2.spawn_sub_agent("agent-b", ["tool:read_file"],
                                       s2.k.agent_s)
        ledger2.revoke(s2.dtok)  # the parent only
        ok2, info2 = _refused(
            lambda: child_ex.call(child_ex._session_identity,
                                  "read_file", path="notes.txt"),
            dt_mod.DelegationRevokedError)
        if not ok2:
            return {"verdict": "break",
                    "note": "child call authorized after its PARENT was "
                            "revoked: %s" % (info2,)}
        # 3. A raising checker fails CLOSED, not loud.
        def _boom(ref):
            raise IOError("revocation source unreachable")

        ex3 = ToolExecutor(
            run_dir2, ex2.policy, ex2.log, ex2.approvals,
            policy_store=ex2._policy_store,
            delegation_context=s2.ctx, revocation_checker=_boom,
            capability_ungoverned_ack=(
                "w86 identity probes: subject under test is "
                "delegation identity, not the capability gate; "
                "declared, not silent"),
            session_identity=("agent-a", "coder", "alice"))
        ok3, info3 = _refused(
            lambda: ex3.call(ex3._session_identity, "read_file",
                             path="notes.txt"),
            dt_mod.DelegationRevokedError)
        if not ok3:
            return {"verdict": "break",
                    "note": "raising revocation checker did not fail "
                            "closed: %s" % (info3,)}
    return {"verdict": "stopped",
            "note": "revocation is wired at the executor gate: revoked "
                    "leaf refused, revoked ancestor refused for the "
                    "child, raising checker fails closed as "
                    "DelegationRevokedError"}


@_sit("redteam.identity_w86.spawn_budget_exhaustion")
def sit_spawn_budget_exhaustion():
    """Closure pin (F133): the spawn budget bounds the whole lineage —
    exhaustion fails closed, and invalid budgets fail closed at
    construction."""
    if not hasattr(ToolExecutor, "spawn_sub_agent"):
        return {"verdict": "break",
                "note": "no governed spawn mouth"}
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        run_dir, _lg, ex, s, _ledger = _governed_executor_for_probe(
            "w86budget-", spawn_budget=1)
        ex.spawn_sub_agent("agent-b", ["tool:read_file"], s.k.agent_s)
        ok, info = _refused(
            lambda: ex.spawn_sub_agent("agent-c", ["tool:read_file"],
                                       s.k.agent_s),
            SpawnBudgetExhaustedError)
        if not ok:
            return {"verdict": "break",
                    "note": "spawn past budget=1 succeeded: %s" % (info,)}
        # Invalid budgets fail closed at construction.
        for bad in (-1, True, "3"):
            okb, infob = _refused(
                lambda: ToolExecutor(
                    run_dir, ex.policy, ex.log,
                    ex.approvals, policy_store=ex._policy_store,
                    delegation_context=s.ctx,
                    session_identity=("agent-a", "coder", "alice"),
                    capability_ungoverned_ack=(
                        "w86 identity probes: subject under test is "
                        "spawn budget, not the capability gate; "
                        "declared, not silent"),
                    spawn_budget=bad),
                ValueError)
            if not okb:
                return {"verdict": "break",
                        "note": "spawn_budget=%r accepted: %s"
                        % (bad, infob)}
    return {"verdict": "stopped",
            "note": "spawn budget enforced: second spawn at budget=1 "
                    "refused (SpawnBudgetExhaustedError); negative/bool/"
                    "str budgets refused at construction"}


@_sit("redteam.identity_w86.depth_cap_verify_side")
def sit_depth_cap_verify_side():
    """Closure pin: a correctly parent-SIGNED deep chain (built
    hand-forged, bypassing issuance) must die at VERIFICATION — the
    depth cap is re-checked on the verify seam, not just at spawn."""
    s = _session()  # depths 0..8
    chain = [s.dtok]
    parent_tok = s.dtok
    for depth in range(1, 10):
        claims = dict(_child_claims(s, parent_tok, depth,
                                    ["tool:read_file"]))
        tok = dt_mod._base_token("delegation", s.k.agent_s, "agent-deep",
                                 s.session_id, claims, None, _T0)
        chain.append(tok)
        parent_tok = tok
    # Control: depth-8 leaf verifies (issuance would have allowed it).
    try:
        DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=chain[8], parent_chain=chain[:8],
            trust=s.trust, session_id=s.session_id).bind(now=_T0)
    except DelegationError as e:
        return {"verdict": "break",
                "note": "control failed: legal depth-8 chain refused: "
                        "%s: %s" % (type(e).__name__, e)}
    # Attack: the depth-9 leaf — every signature valid, issuance never
    # consulted — must die at verification.
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=chain[9], parent_chain=chain[:9],
            trust=s.trust, session_id=s.session_id).bind(now=_T0),
        DelegationAttenuationError)
    if not ok:
        return {"verdict": "break",
                "note": "smuggled depth-9 chain verified: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "hand-forged depth-9 chain (all signatures valid, "
                    "issuance bypassed) refused at verification "
                    "(DelegationAttenuationError); depth-8 control "
                    "verifies"}


@_sit("redteam.identity_w86.child_executor_passes_gate")
def sit_child_executor_passes_gate():
    """Positive closure pin (F133/F55): the spawned child executor is a
    fully governed session — its provisioned identity passes the real
    gate, and run_id == session run_id so the gate's session binding
    holds for the child."""
    if not hasattr(ToolExecutor, "spawn_sub_agent"):
        return {"verdict": "break",
                "note": "no governed spawn mouth"}
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        run_dir, _lg, ex, s, _ledger = _governed_executor_for_probe(
            "w86childgate-")
        child_ex = ex.spawn_sub_agent("agent-b", ["tool:read_file"],
                                      s.k.agent_s)
        if child_ex.run_id != run_dir.name:
            return {"verdict": "break",
                    "note": "child run_id %r != session dir %r"
                            % (child_ex.run_id, run_dir.name)}
        ident = child_ex._session_identity
        if (ident.agent_id, ident.role, ident.principal) != (
                "agent-b", "coder", "alice"):
            return {"verdict": "break",
                    "note": "child identity not provisioned: %r"
                            % (ident,)}
        try:
            res = child_ex.call(ident, "read_file", path="notes.txt")
        except DelegationError as e:
            return {"verdict": "break",
                    "note": "child executor call refused: %s: %s"
                            % (type(e).__name__, e)}
        if res["status"] != "executed":
            return {"verdict": "break",
                    "note": "child call not executed: %r" % (res,)}
    return {"verdict": "stopped",
            "note": "spawned child executor is governed: provisioned "
                    "identity (agent-b/coder/alice) passes the real "
                    "gate, run_id == session run_id"}


@_sit("redteam.identity_w86.depth_cap_evade")
def sit_depth_cap_evade():
    """White-box: MAX_DELEGATION_DEPTH caps the swarm at issuance.
    Build the deepest legal chain (depth 8) — it must verify and
    authorize — then attempt depth 9: refused. (Measured, not a miss:
    chain verify does NOT re-check the cap; issuance is the single
    enforcement point, and only a key-holder can mint deeper.)"""
    s = _session()
    cur = s.ctx
    for i in range(dt_mod.MAX_DELEGATION_DEPTH):
        cur = cur.spawn("sub-%d" % i, ["tool:read_file"],
                        s.k.agent_s, now=_T0)
    if cur._leaf_claims["delegation_depth"] != dt_mod.MAX_DELEGATION_DEPTH:
        return {"verdict": "break",
                "note": "legal depth-%d chain did not build as expected"
                % dt_mod.MAX_DELEGATION_DEPTH}
    try:
        cur.authorize("tool:read_file", now=_T0)
    except DelegationError as e:
        return {"verdict": "break",
                "note": "legal deepest chain failed to authorize: "
                        "%s: %s" % (type(e).__name__, e)}
    ok, info = _refused(
        lambda: cur.spawn("sub-too-deep", ["tool:read_file"],
                          s.k.agent_s, now=_T0),
        DelegationAttenuationError)
    if not ok:
        return {"verdict": "break",
                "note": "depth-%d chain minted: %s"
                % (dt_mod.MAX_DELEGATION_DEPTH + 1, info)}
    return {"verdict": "stopped",
            "note": "depth-%d chain verifies and authorizes; depth %d "
                    "refused at issuance (swarm cap) — and since wave-86 "
                    "verify_delegation_chain ALSO re-checks the cap, a "
                    "hand-forged deep chain dies at verification too "
                    "(see depth_cap_verify_side)"
            % (dt_mod.MAX_DELEGATION_DEPTH,
               dt_mod.MAX_DELEGATION_DEPTH + 1)}


@_sit("redteam.identity_w86.expired_token_use")
def sit_expired_token_use():
    """Tokens are issued 2h ago with the 1h default TTL (expired well
    past the 300s skew), bound while valid, then presented to
    authorize at _T0: bind-time validity must not linger — expiry is
    re-checked per action."""
    s = _session(now=_T0 - timedelta(seconds=7200))
    ok, info = _refused(
        lambda: s.ctx.authorize("tool:read_file", now=_T0),
        DelegationExpiredError)
    if not ok:
        return {"verdict": "break",
                "note": "expired token authorized: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "token expired 1h ago (+300s skew exhausted) "
                    "refused at authorize time — per-action window "
                    "re-check, not bind-time residue"}


@_sit("redteam.identity_w86.future_not_before_refused")
def sit_future_not_before_refused():
    """The not_before side of the window: tokens minted for 2h in the
    future (pre-dated / pre-issued tokens) presented now must be
    refused — the validity window is two-sided."""
    s = _session(now=_T0 + timedelta(seconds=7200))
    ok, info = _refused(
        lambda: s.ctx.authorize("tool:read_file", now=_T0),
        DelegationExpiredError)
    if not ok:
        return {"verdict": "break",
                "note": "pre-dated token authorized: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "token with not_before 2h in the future refused "
                    "(window is [nbf - skew, exp + skew], two-sided)"}


@_sit("redteam.identity_w86.cross_session_replay")
def sit_cross_session_replay():
    """Session-X tokens presented in session Y: the session_id binding
    must refuse replay even when every signature is valid and in
    window."""
    s = _session(session_id="sess-w86-x")
    ctx_y = DelegationContext(
        user_token=s.utok, agent_token=s.atok,
        delegation_token=s.dtok, parent_chain=[],
        trust=s.trust, session_id="sess-w86-y")
    ok, info = _refused(lambda: ctx_y.bind(now=_T0),
                        DelegationBindingError)
    if not ok:
        return {"verdict": "break",
                "note": "session-X tokens bound in session Y: %s"
                % (info,)}
    return {"verdict": "stopped",
            "note": "cross-session replay refused: token bound to "
                    "'sess-w86-x', presented in 'sess-w86-y'"}


@_sit("redteam.identity_w86.unbound_context_authorize")
def sit_unbound_context_authorize():
    """A DelegationContext that was constructed but never bind()ed must
    not authorize — verification is not optional."""
    s = _session()
    unbound = DelegationContext(
        user_token=s.utok, agent_token=s.atok,
        delegation_token=s.dtok, parent_chain=[],
        trust=s.trust, session_id=s.session_id)
    ok, info = _refused(
        lambda: unbound.authorize("tool:read_file", now=_T0),
        DelegationRequiredError)
    if not ok:
        return {"verdict": "break",
                "note": "unbound context authorized: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "unbound context refused: bind (verify) before "
                    "authorizing"}


@_sit("redteam.identity_w86.issuer_keyid_swap")
def sit_issuer_keyid_swap():
    """White-box: the issuer field is attacker-writable JSON. Variant:
    the token names a ROSTERED key_id (a second registered human) but
    the signature was made by the original human's key. The sig covers
    the issuer field, so the swap must die."""
    s = _session()
    h2_s, h2_p = generate_test_keypair()
    trust2 = _trust_for(s.k, extra_humans=[(h2_s, h2_p)])
    tampered = copy.deepcopy(s.dtok)
    tampered["issuer"] = h2_s.key_id  # rostered, but sig is human-1's
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=tampered, parent_chain=[],
            trust=trust2, session_id=s.session_id).bind(now=_T0),
        DelegationSignatureError)
    if not ok:
        return {"verdict": "break",
                "note": "issuer-swapped token bound: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "issuer key_id swapped to a different rostered key "
                    "refused: the signature covers the issuer field"}


@_sit("redteam.identity_w86.parent_signature_key_swap")
def sit_parent_signature_key_swap():
    """White-box on _roster_for_depth: a child that is correctly
    parent-linked and scope-narrowed, but SIGNED by an attacker's key
    (registered in the session roster under a DIFFERENT agent_id)
    while the delegator claim names the real parent. The hop issuer
    must match the session-rostered parent key."""
    s = _session()
    evil_s, evil_p = generate_test_keypair()
    trust = _trust_for(s.k, extra_agents={"agent-evil": evil_p})
    forged = dt_mod._base_token(
        "delegation", evil_s, "agent-b", s.session_id,
        _child_claims(s, s.dtok, 1, ["tool:read_file"],
                      delegator="agent-a"),
        None, _T0)
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=s.utok, agent_token=s.atok,
            delegation_token=forged,
            parent_chain=[s.dtok], trust=trust,
            session_id=s.session_id).bind(now=_T0),
        DelegationSignatureError)
    if not ok:
        return {"verdict": "break",
                "note": "parent-signature-swapped child verified: %s"
                % (info,)}
    if "parent-signature swap" not in str(info):
        return {"verdict": "break",
                "note": "refused but for the wrong reason: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "child signed by a non-parent rostered key refused: "
                    "hop issuer must match the session roster key for "
                    "the claimed parent"}


@_sit("redteam.identity_w86.token_substitution_user_swap")
def sit_token_substitution_user_swap():
    """White-box on South et al.'s binding: the leaf commits to the
    user/agent token hashes. Present the valid delegation with a
    DIFFERENT valid user token (bob's, same session, valid sigs) —
    the binding must catch the substitution."""
    s = _session()
    bob_utok = issue_user_token(s.k.idp_s, "bob", ["tool:read_file"],
                                s.session_id, now=_T0)
    ok, info = _refused(
        lambda: DelegationContext(
            user_token=bob_utok, agent_token=s.atok,
            delegation_token=s.dtok, parent_chain=[],
            trust=s.trust, session_id=s.session_id).bind(now=_T0),
        DelegationSignatureError)
    if not ok:
        return {"verdict": "break",
                "note": "user-token substitution accepted: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "bob's user token presented under alice's "
                    "delegation refused: leaf user_token_hash does not "
                    "match the presented user token"}


@_sit("redteam.identity_w86.spawn_unbound_parent_refused")
def sit_spawn_unbound_parent_refused():
    """spawn() from a parent context that never bound: refused —
    lineage cannot start from an unverified parent."""
    s = _session()
    unbound = DelegationContext(
        user_token=s.utok, agent_token=s.atok,
        delegation_token=s.dtok, parent_chain=[],
        trust=s.trust, session_id=s.session_id)
    ok, info = _refused(
        lambda: unbound.spawn("agent-b", ["tool:read_file"],
                              s.k.agent_s, now=_T0),
        DelegationRequiredError)
    if not ok:
        return {"verdict": "break",
                "note": "spawn from unbound parent issued: %s" % (info,)}
    return {"verdict": "stopped",
            "note": "spawn from an unbound parent refused: spawn "
                    "requires a BOUND parent DelegationContext"}


@_sit("redteam.identity_w86.missing_delegation_fails_closed")
def sit_missing_delegation_fails_closed():
    """The agent-without-delegation case, twice: enforce_tool_call
    with NO context, and bind() on a context carrying NO delegation
    token. Both must fail closed by construction (in code, not policy
    text)."""
    s = _session()
    ident = AgentIdentity("agent-a", "coder", s.session_id, "alice")
    ok_a, info_a = _refused(
        lambda: enforce_tool_call(None, ident, "read_file", now=_T0),
        DelegationRequiredError)
    no_tok = DelegationContext(
        user_token=s.utok, agent_token=s.atok,
        delegation_token=None, parent_chain=[],
        trust=s.trust, session_id=s.session_id)
    ok_b, info_b = _refused(lambda: no_tok.bind(now=_T0),
                            DelegationRequiredError)
    if not (ok_a and ok_b):
        return {"verdict": "break",
                "note": "missing-delegation holes: no-context=%s "
                        "no-token=%s" % (info_a, info_b)}
    return {"verdict": "stopped",
            "note": "agent-without-delegation fails closed on both "
                    "mouths: no context at the executor gate, no token "
                    "at bind"}


@_sit("redteam.identity_w86.revocation_propagates_to_descendants")
def sit_revocation_propagates_to_descendants():
    """The revocation seam: a revoked leaf refuses, and a revoked
    PARENT invalidates the child's authorize — revocation propagates
    down the chain (the point of the seam)."""
    s = _session()
    ledger = dt_mod.RevocationLedger()
    ledger.revoke(s.dtok)
    ok_leaf, info_leaf = _refused(
        lambda: s.ctx.authorize("tool:read_file", now=_T0,
                                revocation_checker=ledger),
        dt_mod.DelegationRevokedError)
    ledger2 = dt_mod.RevocationLedger()
    child = s.ctx.spawn("agent-b", ["tool:read_file"], s.k.agent_s,
                        now=_T0)
    ledger2.revoke(s.dtok)  # revoke the PARENT only
    ok_child, info_child = _refused(
        lambda: child.authorize("tool:read_file", now=_T0,
                                revocation_checker=ledger2),
        dt_mod.DelegationRevokedError)
    if not (ok_leaf and ok_child):
        return {"verdict": "break",
                "note": "revocation holes: leaf=%s child-of-revoked=%s"
                % (info_leaf, info_child)}
    return {"verdict": "stopped",
            "note": "revocation seam holds: revoked leaf refused and a "
                    "revoked parent invalidates the descendant chain"}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    counts = {"stopped": 0, "break": 0, "residual": 0}
    for r in RESULTS:
        v = r["verdict"]
        counts[v if v in counts else "break"] += 1
    for r in RESULTS:
        print("%-58s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w86 battery: %d STOPPED / %d RESIDUAL / %d BREAK|ERROR"
          % (counts["stopped"], counts["residual"], counts["break"]))
    out = {"battery": "redteam.identity_w86", "counts": counts,
           "probes": RESULTS}
    (REPO_ROOT / "evals" / "w86_results.json").write_text(
        json.dumps(out, indent=2), encoding="utf-8")
    return 1 if counts["break"] else 0


if __name__ == "__main__":
    sys.exit(main())
