"""Wave-74 break-first probes (2026-09-22): the three-token identity.

The delegation behind the envelope: every governed action runs under a
user token (IdP), an agent token (registration authority), and a
HUMAN-signed delegation token binding the two by hash, with
parent-signed, monotonically-attenuating spawn lineage. Break-first:
every attack probe must end with the identity layer refusing — verdict
"stopped" means the ATTACK was stopped (refused/detected); "break"
means the identity layer failed to catch it.

  FORGERY:
    delegation_forgery_refused -- re-sign the delegation with an
      attacker's key, or tamper a signed scope claim: verification
      must refuse (Ed25519, not HMAC: the verifier cannot forge).
  SCOPE ESCALATION:
    scope_escalation_refused -- spawn a sub-agent with a WIDER scope
      than the parent: refused at issuance; a parent-signed wider
      child is refused again at chain verification (monotonicity is
      re-checked, not trusted).
  MISSING DELEGATION (construction proof):
    missing_delegation_fails_closed -- install the executor's
      delegation gate under an ALLOW-ALL policy: a call with no
      delegation token must raise DelegationRequiredError in CODE
      before policy evaluation, get audit-logged, and never execute.
  CROSS-SESSION REPLAY:
    cross_session_replay_refused -- a token minted for session A is
      replayed in session B: refused at verify time and at the
      executor gate.
  EXPIRY / SKEW:
    expiry_and_skew_enforced -- an expired token is refused; expiry
      inside the +/-300s skew window is tolerated; past the window it
      is refused again.
  PARENT-SIGNATURE SWAP:
    parent_signature_swap_refused -- a child signed by a key that is
      not the session-registered parent key, and a correctly-signed
      child spliced onto a different parent hash: both refused.
  MIDDLE-HOP TRUNCATION (through the Wave-73 validator):
    middle_hop_truncation_detected -- drop the middle hop of a v2
      (token-filled) delegation: validate_delegation must report a
      binds mismatch.
  CONTROL:
    valid_chain_authorizes -- the full valid chain binds, authorizes,
      spawns, and executes under a normal policy (green closure).

All runs synthetic/local, $0. Deterministic except wall-clock iat/exp
(never asserted on). Env hygiene restores every mutated variable and
the gov.log dev flags in finally.
"""

import contextlib
import copy
import io
import os
import sys
import tempfile
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))

from gov import delegation_tokens as dt_mod  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov import provenance as prov_mod  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

RESULTS = []
SITUATIONS = {}

_KEY_ENV = ("GOV_LOG_KEY", "GOV_LOG_KEY_EPOCH", "GOV_LOG_KEY_ARCHIVE",
            "GOV_DEPLOYMENT_MODE", "GOV_KEYRING_FILE")


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
    """Wave-81: explicit test-key provisioning.

    Replaces the deleted gov.log dev-key opt-in. With enabled=True,
    yields with an explicit random GOV_LOG_KEY/GOV_LOG_KEY_EPOCH set
    and GOV_LOG_KEY_ARCHIVE cleared, restoring everything afterwards.
    enabled=False is a plain passthrough (no key provisioned).
    """
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
    run_tmp = tempfile.mkdtemp(prefix="w74probe-")
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
                if not isinstance(detail, dict):
                    detail = {"note": str(detail)}
                verdict = detail.pop("verdict", "stopped")
                RESULTS.append({"id": sid, "verdict": verdict,
                                "detail": detail})
            except Exception as e:  # noqa: BLE001 - probe must not die
                RESULTS.append({"id": sid, "verdict": "error",
                                "detail": {"error": "%s: %s"
                                           % (type(e).__name__, e)}})
        wrapper.__name__ = fn.__name__
        wrapper.__doc__ = fn.__doc__
        SITUATIONS[sid] = wrapper
        return wrapper
    return deco


_SID = "sess-w74-probe"
_REVOKE_URI = "https://revoke.example.invalid/deleg"

_ALLOW_ALL = """\
version: 2
roles:
  scout: [read_file, api_call, send_email]
policies:
  - id: allow-all
    effect: allow
    match:
      tool: [read_file, api_call, send_email]
    reason: allow-all fixture
"""


class _Keys(object):
    def __init__(self):
        self.human = dt_mod.generate_test_keypair()
        self.idp = dt_mod.generate_test_keypair()
        self.authority = dt_mod.generate_test_keypair()
        self.parent = dt_mod.generate_test_keypair()

    def trust(self):
        return dt_mod.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={"agent-1": self.parent[1]})


def _trio(keys, session=_SID, **kw):
    user_tok = dt_mod.issue_user_token(
        keys.idp[0], "user-7",
        ("tool:read_file", "tool:send_email"), session, **kw)
    agent_tok = dt_mod.issue_agent_token(
        keys.authority[0], "agent-1", "scout", "user-7",
        ("tool:read_file", "tool:send_email"), session, **kw)
    deleg_tok = dt_mod.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file",), session, _REVOKE_URI, **kw)
    return user_tok, agent_tok, deleg_tok


def _executor(run_tmp, delegation_ctx=None, policy_text=_ALLOW_ALL,
              agent_id="agent-1"):
    run_dir = Path(run_tmp) / ("run-%s" % agent_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    policy_path = run_dir / "policy.yaml"
    policy_path.write_text(policy_text)
    log = ActionLog(run_dir / "actions.jsonl")
    ex = ToolExecutor(run_dir, PolicyEngine(str(policy_path)), log,
                      ApprovalQueue(run_dir, log),
                      ledger_path=run_dir / "egress_ledger.jsonl")
    identity = ex.mint_identity(agent_id, "scout", "user-7")
    if delegation_ctx is not None:
        ex._delegation_context = delegation_ctx
    return ex, identity, run_dir


def _bound_ctx(keys, session):
    user_tok, agent_tok, deleg_tok = _trio(keys, session=session)
    ctx = dt_mod.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[],
        trust=keys.trust(), session_id=session).bind()
    return ctx, (user_tok, agent_tok, deleg_tok)


# ----------------------------------------------------------------------
# Forgery
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.delegation_forgery_refused")
def sit_delegation_forgery_refused():
    """Re-sign the delegation with an attacker's key / tamper a signed
    claim: verification must refuse (Ed25519: the verifier cannot
    forge the human's signature)."""
    keys = _Keys()
    trust = keys.trust()
    _, _, deleg_tok = _trio(keys)
    attacker = dt_mod.generate_test_keypair()

    forged = copy.deepcopy(deleg_tok)
    body = {k: v for k, v in forged.items() if k != "sig"}
    forged["sig"] = attacker[0].sign(
        dt_mod._TOKEN_DOMAIN + dt_mod._canonical(body)).hex()
    try:
        dt_mod.verify_token(forged, trust.human_keys,
                            expected_kind="delegation",
                            expected_session=_SID)
        return {"verdict": "break",
                "note": "attacker-resigned delegation verified"}
    except dt_mod.DelegationSignatureError:
        pass

    tampered = copy.deepcopy(deleg_tok)
    tampered["claims"] = dict(tampered["claims"])
    tampered["claims"]["scope"] = ["tool:*"]
    try:
        dt_mod.verify_token(tampered, trust.human_keys,
                            expected_kind="delegation",
                            expected_session=_SID)
        return {"verdict": "break",
                "note": "scope-tampered delegation verified"}
    except dt_mod.DelegationSignatureError:
        pass
    return {"verdict": "stopped",
            "note": "resigned and tampered delegations both refused"}


# ----------------------------------------------------------------------
# Scope escalation
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.scope_escalation_refused")
def sit_scope_escalation_refused():
    """Spawn wider than the parent: refused at issuance; a
    parent-signed wider child is refused again at chain verification."""
    keys = _Keys()
    ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys, _SID)
    try:
        ctx.spawn("sub-evil", ["tool:send_email"], keys.parent[0])
        return {"verdict": "break",
                "note": "escalating spawn issued"}
    except dt_mod.DelegationAttenuationError:
        pass

    now = datetime.now(timezone.utc)
    iso = now.isoformat()
    body = {
        "token_version": dt_mod.TOKEN_VERSION, "token_kind": "delegation",
        "issuer": keys.parent[0].key_id, "subject": "sub-evil",
        "issued_at": iso, "not_before": iso,
        "expires_at": (now + timedelta(seconds=3600)).isoformat(),
        "session_id": _SID,
        "claims": {
            "delegator": "agent-1",
            "user_token_hash": dt_mod.token_ref(user_tok),
            "agent_token_hash": dt_mod.token_ref(agent_tok),
            "scope": ["tool:read_file", "tool:send_email"],
            "revocation_endpoint": _REVOKE_URI, "audit_urls": [],
            "delegation_depth": 1,
            "parent_token_hash": dt_mod.token_ref(deleg_tok),
        },
    }
    body["sig"] = keys.parent[0].sign(
        dt_mod._TOKEN_DOMAIN + dt_mod._canonical(body)).hex()
    try:
        dt_mod.verify_delegation_chain(
            body, [deleg_tok], keys.trust(), user_tok, agent_tok,
            expected_session=_SID)
        return {"verdict": "break",
                "note": "parent-signed wider child verified"}
    except dt_mod.DelegationAttenuationError:
        pass
    return {"verdict": "stopped",
            "note": "escalation refused at issuance and at chain verify"}


# ----------------------------------------------------------------------
# Missing delegation (construction proof)
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.missing_delegation_fails_closed")
def sit_missing_delegation_fails_closed():
    """Gate installed + ALLOW-ALL policy + no delegation token: the
    call must die in CODE before policy evaluation, be audit-logged,
    and never execute."""
    keys = _Keys()
    with _govrun() as run_tmp:
        ex, identity, run_dir = _executor(run_tmp)
        user_tok, agent_tok, _ = _trio(keys, session=identity.run_id)
        ctx = dt_mod.DelegationContext(
            user_token=user_tok, agent_token=agent_tok,
            delegation_token=None, parent_chain=[],
            trust=keys.trust(), session_id=identity.run_id)
        ex._delegation_context = ctx
        try:
            ex.call(identity, "read_file", path="notes.txt")
            return {"verdict": "break",
                    "note": "call without delegation executed under "
                    "allow-all policy"}
        except dt_mod.DelegationRequiredError:
            pass
        denied = [e for e in read_entries(run_dir / "actions.jsonl")
                  if e.get("event") == "tool_call"
                  and e.get("decision") == "denied"
                  and e.get("policy_id") == "delegation-required"]
        if not denied:
            return {"verdict": "break",
                    "note": "refusal not audit-logged"}
        if ex._executed.get("read_file", 0):
            return {"verdict": "break", "note": "tool executed anyway"}
        return {"verdict": "stopped",
                "note": "missing delegation raised in code despite "
                "allow-all policy; refusal audited; tool never ran"}


# ----------------------------------------------------------------------
# Cross-session replay
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.cross_session_replay_refused")
def sit_cross_session_replay_refused():
    """A token minted for session A replayed in session B: refused at
    verify time and at the executor gate."""
    keys = _Keys()
    trust = keys.trust()
    _, _, deleg_tok = _trio(keys, session="sess-A")
    try:
        dt_mod.verify_token(deleg_tok, trust.human_keys,
                            expected_kind="delegation",
                            expected_session="sess-B")
        return {"verdict": "break",
                "note": "cross-session token verified"}
    except dt_mod.DelegationBindingError:
        pass

    with _govrun() as run_tmp:
        ex, identity, run_dir = _executor(run_tmp)
        ctx, _ = _bound_ctx(keys, "sess-A")
        ex._delegation_context = ctx
        try:
            ex.call(identity, "read_file", path="notes.txt")
            return {"verdict": "break",
                    "note": "cross-session context executed at the gate"}
        except dt_mod.DelegationBindingError:
            pass
    return {"verdict": "stopped",
            "note": "replay refused at verify time and at the gate"}


# ----------------------------------------------------------------------
# Expiry / skew
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.expiry_and_skew_enforced")
def sit_expiry_and_skew_enforced():
    """Expired tokens are refused; expiry inside +/-300s skew is
    tolerated; past the window it is refused again."""
    keys = _Keys()
    trust = keys.trust()
    now = datetime.now(timezone.utc)
    expired = now - timedelta(seconds=4000)
    user_tok, _, _ = _trio(keys, ttl_s=3600, now=expired)
    try:
        dt_mod.verify_token(user_tok, trust.user_issuer_keys,
                            expected_kind="user",
                            expected_session=_SID)
        return {"verdict": "break", "note": "expired token verified"}
    except dt_mod.DelegationExpiredError:
        pass

    near = now - timedelta(seconds=3700)  # 100s past expiry: in skew
    user_tok2, _, _ = _trio(keys, ttl_s=3600, now=near)
    try:
        dt_mod.verify_token(user_tok2, trust.user_issuer_keys,
                            expected_kind="user",
                            expected_session=_SID)
    except dt_mod.DelegationExpiredError:
        return {"verdict": "break",
                "note": "in-skew token refused (skew not honored)"}
    return {"verdict": "stopped",
            "note": "expired refused; in-skew tolerated (clock-skew "
            "acceptance, not a bypass)"}


# ----------------------------------------------------------------------
# Parent-signature swap
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.parent_signature_swap_refused")
def sit_parent_signature_swap_refused():
    """A child signed by a non-roster key, and a correctly-signed child
    spliced onto a different parent hash: both refused."""
    keys = _Keys()
    ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(keys, _SID)
    attacker = dt_mod.generate_test_keypair()
    try:
        ctx.spawn("sub-x", ["tool:read_file"], attacker[0])
        return {"verdict": "break",
                "note": "child signed by unregistered key bound"}
    except dt_mod.DelegationSignatureError:
        pass

    # Splice: a validly parent-signed child that cites a DIFFERENT
    # parent's hash.
    _, (_, _, deleg_tok_b) = _bound_ctx(keys, _SID)
    now = datetime.now(timezone.utc)
    iso = now.isoformat()
    body = {
        "token_version": dt_mod.TOKEN_VERSION, "token_kind": "delegation",
        "issuer": keys.parent[0].key_id, "subject": "sub-x",
        "issued_at": iso, "not_before": iso,
        "expires_at": (now + timedelta(seconds=3600)).isoformat(),
        "session_id": _SID,
        "claims": {
            "delegator": "agent-1",
            "user_token_hash": dt_mod.token_ref(user_tok),
            "agent_token_hash": dt_mod.token_ref(agent_tok),
            "scope": ["tool:read_file"],
            "revocation_endpoint": _REVOKE_URI, "audit_urls": [],
            "delegation_depth": 1,
            "parent_token_hash": dt_mod.token_ref(deleg_tok_b),
        },
    }
    body["sig"] = keys.parent[0].sign(
        dt_mod._TOKEN_DOMAIN + dt_mod._canonical(body)).hex()
    try:
        dt_mod.verify_delegation_chain(
            body, [deleg_tok], keys.trust(), user_tok, agent_tok,
            expected_session=_SID)
        return {"verdict": "break",
                "note": "spliced parent hash verified"}
    except dt_mod.DelegationSignatureError:
        pass
    return {"verdict": "stopped",
            "note": "unregistered-key child and spliced parent both "
            "refused"}


# ----------------------------------------------------------------------
# Middle-hop truncation through the Wave-73 validator
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.middle_hop_truncation_detected")
def sit_middle_hop_truncation_detected():
    """Drop the middle hop of a v2 (token-filled) delegation: the
    Wave-73 binds validator must report the break."""
    keys = _Keys()
    user_tok, agent_tok, deleg_tok = _trio(keys)
    refs = dt_mod.hop_token_refs(user_tok, agent_tok, deleg_tok)
    d = prov_mod.build_delegation([
        {"kind": "principal", "ref": "user:user-7",
         "tokens": dict(refs)},
        {"kind": "agent", "ref": "agent:agent-1", "tokens": dict(refs)},
        {"kind": "sub-agent", "ref": "agent:sub-1",
         "tokens": dict(refs)},
    ])
    assert d["delegation_schema_version"] == 2
    assert prov_mod.validate_delegation(d) == []
    d["hops"] = [d["hops"][0], d["hops"][2]]  # drop the middle hop
    errors = prov_mod.validate_delegation(d)
    if not any("binds mismatch" in e for e in errors):
        return {"verdict": "break",
                "note": "middle-hop drop passed the v2 validator: %r"
                % (errors,)}
    return {"verdict": "stopped",
            "note": "middle-hop truncation broke the binds chain on v2"}


# ----------------------------------------------------------------------
# Control
# ----------------------------------------------------------------------

@_sit("redteam.identity_w74.valid_chain_authorizes")
def sit_valid_chain_authorizes():
    """The full valid chain binds, authorizes, spawns, and executes
    under a normal policy (green closure control)."""
    keys = _Keys()
    with _govrun() as run_tmp:
        ex, identity, run_dir = _executor(run_tmp)
        ctx, (user_tok, agent_tok, deleg_tok) = _bound_ctx(
            keys, identity.run_id)
        ex._delegation_context = ctx
        r = ex.call(identity, "read_file", path="notes.txt")
        if r["status"] != "executed":
            return {"verdict": "break",
                    "note": "valid chain did not execute: %r" % (r,)}
        child = ctx.spawn("sub-1", ["tool:read_file"], keys.parent[0])
        verdict = child.authorize("tool:read_file")
        if not all(verdict["allowed_by"].values()):
            return {"verdict": "break",
                    "note": "spawned child did not authorize"}
        ctx2, delegation = prov_mod.open_delegated_session(
            user_tok, agent_tok, deleg_tok, keys.trust(),
            identity.run_id)
        if not ctx2.bound or prov_mod.validate_delegation(
                delegation):
            return {"verdict": "break",
                    "note": "session-open chaining failed"}
    return {"verdict": "stopped",
            "note": "valid chain: bind OK, authorize OK, spawn OK, "
            "execute OK, session-open chaining OK (green control)"}


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    n_hold = sum(1 for r in RESULTS if r["verdict"] == "stopped")
    n_miss = sum(1 for r in RESULTS if r["verdict"] not in ("stopped",))
    for r in RESULTS:
        print("%-62s %s  %s" % (r["id"], r["verdict"],
                                r["detail"].get("note", "")))
    print("w74 battery: %d HOLD / %d MISS|ERROR" % (n_hold, n_miss))
    return 1 if n_miss else 0


if __name__ == "__main__":
    sys.exit(main())
