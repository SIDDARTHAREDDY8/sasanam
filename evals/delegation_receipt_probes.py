"""Red-first break battery: cross-app delegation receipts (Row 18 residual).

Gap (pre-seam): the delegation stack authenticates (F132/F133/F135) but
audit attribution blends human and agent identity — the authorization
verdict carries token refs but no readable ``sub`` (on whose behalf)
vs ``act`` (who acts) claims, and no verifier exists that can refuse a
forged attribution. This is the borrowed-credential log-attribution gap
(the Okta Cross-App-Access protocol shape: distinct act/sub claims;
protocol idea only — no copied code, no encumbrance).

RED FIRST: run this battery against the tree BEFORE the seam lands and
it must show 0 HELD / 12 BREAK (every probe breaks on the missing seam:
no receipt API, no verifier, no sub/act on the verdict). After the seam
lands it must go 12 HELD / 0 BREAK.

Determinism: synthetic Ed25519 keys, fixed session ids, explicit ``now``
on every issuance — no wall-clock dependence. Every probe runs twice
internally; the whole battery runs twice per environment.

Module-level staging mode: the harness's declared ungoverned_ack is
refused in production mode, so batteries must pin staging here.
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import sys
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import delegation_tokens as _dt

_NOW = datetime(2026, 9, 27, 12, 0, 0, tzinfo=timezone.utc)
_SID = "sess-receipt"
_REVOKE_URI = "https://revoke.example.invalid/deleg"


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self, extra_agent_keys=None):
        agent_keys = {"agent-1": self.parent[1]}
        if extra_agent_keys:
            agent_keys.update(extra_agent_keys)
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys=agent_keys)


def _trio(keys, user_id="user-7", agent_id="agent-1", session=_SID,
          user_scope=("tool:read_file", "tool:send_email"),
          agent_scope=("tool:read_file", "tool:send_email"),
          deleg_scope=("tool:read_file",), now=_NOW):
    user_tok = _dt.issue_user_token(keys.idp[0], user_id, user_scope,
                                    session, now=now)
    agent_tok = _dt.issue_agent_token(keys.authority[0], agent_id,
                                      "scout", user_id, agent_scope,
                                      session, now=now)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], user_id, user_tok, agent_tok, deleg_scope,
        session, _REVOKE_URI, now=now)
    return user_tok, agent_tok, deleg_tok


def _bound_ctx(keys, trust=None, session=_SID, now=_NOW, **trio_kw):
    toks = _trio(keys, session=session, now=now, **trio_kw)
    ctx = _dt.DelegationContext(
        user_token=toks[0], agent_token=toks[1], delegation_token=toks[2],
        parent_chain=[], trust=trust or keys.trust(),
        session_id=session).bind(now=now)
    return ctx, toks


def _seam():
    """The new-seam API, or None pre-seam (every probe then BREAKs)."""
    if hasattr(_dt, "delegation_receipt") and hasattr(
            _dt, "verify_delegation_receipt"):
        return (_dt.delegation_receipt, _dt.verify_delegation_receipt)
    return None


def _verify_args(keys, toks, trust=None, session=_SID, now=_NOW):
    return dict(user_token=toks[0], agent_token=toks[1],
                delegation_token=toks[2], parent_chain=[],
                trust=trust or keys.trust(), session_id=session, now=now)


class ReceiptProbe(object):
    """One probe: name + fn returning (held: bool, detail: str).

    held=True means the GOOD property holds. Pre-seam every probe must
    report held=False (the gap); post-seam held=True. Each probe runs
    twice internally and must agree (determinism pin).
    """

    def __init__(self, name, fn):
        self.name = name
        self.fn = fn

    def run(self):
        results = [self.fn() for _ in range(2)]
        if results[0][0] != results[1][0]:
            return False, "NONDETERMINISTIC: %r vs %r" % (results[0],
                                                          results[1])
        return results[0]


def p_api_exists():
    api = _seam()
    if api is None:
        return False, "BREAK: no delegation_receipt/verify_delegation_receipt"
    return True, "HELD: receipt API present"


def p_verdict_carries_attribution():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    keys = _Keys()
    ctx, _ = _bound_ctx(keys)
    verdict = _dt.authorize_action(ctx, "tool:read_file", now=_NOW)
    receipt = verdict.get("receipt")
    if not isinstance(receipt, dict):
        return False, "BREAK: authorize verdict carries no receipt"
    if receipt.get("sub") != "user-7":
        return False, "BREAK: receipt.sub=%r, want 'user-7'" % (
            receipt.get("sub"),)
    if receipt.get("act") != "agent-1":
        return False, "BREAK: receipt.act=%r, want 'agent-1'" % (
            receipt.get("act"),)
    return True, "HELD: verdict.receipt sub=user-7 act=agent-1"


def p_forged_sub_refused():
    api = _seam()
    if api is None:
        return False, "BREAK: no verifier exists to refuse a forged sub"
    mint, verify = api
    keys = _Keys()
    ctx, toks = _bound_ctx(keys)
    forged = deepcopy(mint(ctx))
    forged["sub"] = "cfo-admin"  # attacker claims a loftier principal
    try:
        verify(forged, **_verify_args(keys, toks))
    except _dt.DelegationError:
        return True, "HELD: forged sub refused"
    return False, "BREAK: forged sub user-7->cfo-admin VERIFIED"


def p_act_sub_distinct():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, _ = api
    keys = _Keys()
    ctx, _ = _bound_ctx(keys)
    receipt = mint(ctx)
    if receipt.get("sub") == receipt.get("act"):
        return False, "BREAK: sub and act blended"
    if receipt["delegation_token_ref"] == receipt["user_token_ref"]:
        return False, "BREAK: token refs not distinct"
    return True, "HELD: sub=%r act=%r refs distinct" % (
        receipt["sub"], receipt["act"])


def p_chain_attribution():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, verify = api
    keys = _Keys()
    ctx, toks = _bound_ctx(keys)
    child = ctx.spawn("agent-2", ["tool:read_file"], keys.parent[0],
                      now=_NOW)
    trust = keys.trust(extra_agent_keys={"agent-2": keys.parent[1]})
    receipt = mint(child)
    chain = receipt.get("delegator_chain")
    if not isinstance(chain, list) or len(chain) != 2:
        return False, "BREAK: delegator_chain len=%r, want 2" % (
            len(chain) if isinstance(chain, list) else chain,)
    if chain[0].get("delegator") != "user-7" or chain[0].get("depth") != 0:
        return False, "BREAK: hop0=%r, want human user-7 depth 0" % (
            chain[0],)
    if chain[1].get("delegator") != "agent-1" or chain[1].get("depth") != 1:
        return False, "BREAK: hop1=%r, want parent agent-1 depth 1" % (
            chain[1],)
    if receipt.get("sub") != "user-7":
        return False, "BREAK: sub=%r, want originating user-7" % (
            receipt.get("sub"),)
    if receipt.get("act") != "agent-2":
        return False, "BREAK: act=%r, want leaf agent-2" % (
            receipt.get("act"),)
    # The full chain must verify with the parent hop presented.
    try:
        verify(receipt, user_token=toks[0], agent_token=toks[1],
               delegation_token=child.delegation_token,
               parent_chain=[toks[2]], trust=trust, session_id=_SID,
               now=_NOW)
    except _dt.DelegationError as e:
        return False, "BREAK: valid depth-2 receipt refused: %s" % e
    return True, "HELD: depth-2 chain human->parent->leaf attributed"


def p_tampered_scope_refused():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, verify = api
    keys = _Keys()
    ctx, toks = _bound_ctx(keys)
    tampered = deepcopy(mint(ctx))
    tampered["scope"] = ["tool:*"]  # attacker widens the receipt's scope
    try:
        verify(tampered, **_verify_args(keys, toks))
    except _dt.DelegationError:
        return True, "HELD: scope-widened receipt refused"
    return False, "BREAK: scope-widened receipt VERIFIED"


def p_unbound_refused():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, _ = api
    keys = _Keys()
    toks = _trio(keys)
    unbound = _dt.DelegationContext(
        user_token=toks[0], agent_token=toks[1], delegation_token=toks[2],
        parent_chain=[], trust=keys.trust(), session_id=_SID)
    try:
        mint(unbound)
    except _dt.DelegationRequiredError:
        return True, "HELD: unbound context cannot mint"
    except _dt.DelegationError:
        return True, "HELD: unbound mint refused (DelegationError)"
    return False, "BREAK: unbound context minted a receipt"


def p_wrong_session_refused():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, verify = api
    keys = _Keys()
    ctx, toks = _bound_ctx(keys)
    receipt = mint(ctx)
    args = _verify_args(keys, toks)
    args["session_id"] = "sess-other"  # cross-session replay
    try:
        verify(receipt, **args)
    except _dt.DelegationError:
        return True, "HELD: cross-session receipt refused"
    return False, "BREAK: receipt verified in a foreign session"


def p_no_token_bodies():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, _ = api
    keys = _Keys()
    ctx, _ = _bound_ctx(keys)
    import json
    blob = json.dumps(mint(ctx), sort_keys=True)
    if '"sig"' in blob:
        return False, "BREAK: receipt embeds a token signature"
    if "claims" in blob:
        return False, "BREAK: receipt embeds token claim bodies"
    return True, "HELD: receipt carries refs+ids only, no bodies/sigs"


def p_name_collision_attributable():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, verify = api
    keys = _Keys()
    # Adversarial naming: the agent id equals the user id string.
    ctx, toks = _bound_ctx(keys, agent_id="user-7")
    receipt = mint(ctx)
    if receipt.get("sub") != "user-7" or receipt.get("act") != "user-7":
        return False, "BREAK: sub/act wrong under name collision"
    if receipt["delegation_token_ref"] == receipt["user_token_ref"]:
        return False, "BREAK: refs collide under name collision"
    try:
        verify(receipt, **_verify_args(keys, toks))
    except _dt.DelegationError as e:
        return False, "BREAK: valid receipt refused: %s" % e
    return True, "HELD: sub==act as strings, refs keep them distinct"


def p_dropped_hop_refused():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, verify = api
    keys = _Keys()
    ctx, toks = _bound_ctx(keys)
    child = ctx.spawn("agent-2", ["tool:read_file"], keys.parent[0],
                      now=_NOW)
    trust = keys.trust(extra_agent_keys={"agent-2": keys.parent[1]})
    receipt = mint(child)
    dropped = deepcopy(receipt)
    dropped["delegator_chain"] = dropped["delegator_chain"][:1]  # drop hop
    try:
        verify(dropped, user_token=toks[0], agent_token=toks[1],
               delegation_token=child.delegation_token,
               parent_chain=[toks[2]], trust=trust, session_id=_SID,
               now=_NOW)
    except _dt.DelegationError:
        return True, "HELD: hop-dropped receipt refused"
    return False, "BREAK: hop-dropped receipt VERIFIED"


def p_reordered_chain_refused():
    api = _seam()
    if api is None:
        return False, "BREAK: seam missing"
    mint, verify = api
    keys = _Keys()
    ctx, toks = _bound_ctx(keys)
    child = ctx.spawn("agent-2", ["tool:read_file"], keys.parent[0],
                      now=_NOW)
    trust = keys.trust(extra_agent_keys={"agent-2": keys.parent[1]})
    receipt = mint(child)
    swapped = deepcopy(receipt)
    swapped["delegator_chain"] = list(reversed(swapped["delegator_chain"]))
    try:
        verify(swapped, user_token=toks[0], agent_token=toks[1],
               delegation_token=child.delegation_token,
               parent_chain=[toks[2]], trust=trust, session_id=_SID,
               now=_NOW)
    except _dt.DelegationError:
        return True, "HELD: hop-reordered receipt refused"
    return False, "BREAK: hop-reordered receipt VERIFIED"


PROBES = [
    ReceiptProbe("api_exists", p_api_exists),
    ReceiptProbe("verdict_carries_attribution", p_verdict_carries_attribution),
    ReceiptProbe("forged_sub_refused", p_forged_sub_refused),
    ReceiptProbe("act_sub_distinct", p_act_sub_distinct),
    ReceiptProbe("chain_attribution", p_chain_attribution),
    ReceiptProbe("tampered_scope_refused", p_tampered_scope_refused),
    ReceiptProbe("unbound_refused", p_unbound_refused),
    ReceiptProbe("wrong_session_refused", p_wrong_session_refused),
    ReceiptProbe("no_token_bodies", p_no_token_bodies),
    ReceiptProbe("name_collision_attributable", p_name_collision_attributable),
    ReceiptProbe("dropped_hop_refused", p_dropped_hop_refused),
    ReceiptProbe("reordered_chain_refused", p_reordered_chain_refused),
]


def main():
    held, brk, err = 0, 0, 0
    for probe in PROBES:
        try:
            ok, detail = probe.run()
        except Exception as e:  # noqa: BLE001 - battery must not die
            err += 1
            print("ERROR %-28s %s: %s" % (probe.name,
                                          type(e).__name__, e))
            continue
        if ok:
            held += 1
            print("HELD  %-28s %s" % (probe.name, detail))
        else:
            brk += 1
            print("BREAK %-28s %s" % (probe.name, detail))
    print("----")
    print("%d HELD / %d BREAK / %d ERROR" % (held, brk, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
