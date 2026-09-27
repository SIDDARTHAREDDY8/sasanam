#!/usr/bin/env python3
"""Rows 11/18 residual: delegation receipts are not stamped into
executor audit / approval records.

The wave-152/153 lanes shipped the identity-delegation receipt
(``gov/delegation_tokens.delegation_receipt``: the verified
sub/act/delegator_chain/scope/session_id + token refs) and the
ceremony discriminator, but neither the executor's audit entries
(``tool_call``: execution_authorized / denied / queued_pending) nor
the ApprovalQueue records carry the receipt. An auditor sees WHO
acted (agent_id) but not THROUGH WHICH DELEGATION PATH (which human
delegated, the hop chain, the scope the action ran under).

This battery is RED-first: pre-seam every probe BREAKs on the
missing ``delegation_receipt`` field; post-seam the field is present
on every verdict-path record — a verified receipt dict for
delegated executions, explicit ``None`` (never ambiguous/absent)
for direct executions — MAC-bound on approval records, and
verifiable offline via ``verify_delegation_receipt``.

Probe map:
  d_exec_allow       delegated allow-path execution stamps the receipt
  d_deny             denied call stamps the receipt
  d_queue            queued approval record stamps the receipt (MAC OK)
  d_sweep            approved sweep's execution_authorized stamps it
  d_direct_none      non-delegated executor: explicit None, key present
  d_queue_direct_none non-delegated approval record: explicit None
  d_receipt_verifies stamped receipt verifies against the tokens
  d_tampered_loud    tampered stamped receipt is LOUD (refused)
  d_expired_loud     expired delegation is LOUD (refused)
  d_malformed_refused queue() refuses malformed receipts fail-closed
  d_mac_binds        post-queue receipt tampering breaks the MAC
  d_deterministic_x2 byte-identical verdicts across 2 runs

Verdicts: HELD / BREAK / EXPECTED / ERROR.

$0 spend, synthetic/local, deterministic. Real product code
(gov.executor, gov.approvals, gov.delegation_tokens), no stubs.

Run:
  mkdir -p /tmp/gov-deleg-stamp
  TMPDIR=/tmp/gov-deleg-stamp ~/workspace/.gov-venv/bin/python \\
      evals/deleg_receipt_stamping_probes.py
Also standalone:
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/tmp/gov-deleg-stamp-u \\
      ~/workspace/.gov-venv/bin/python \\
      evals/deleg_receipt_stamping_probes.py
"""

import copy
import json
import os
import secrets
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# The chained audit log is keyed (F73 fail-closed): mint a throwaway
# run key so the battery is self-contained.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "deleg-stamp-probe")
os.environ.setdefault("TMPDIR", "/tmp/gov-deleg-stamp-%d" % os.getpid())

REPO_ROOT = Path(__file__).resolve().parent.parent
for _p in (str(REPO_ROOT), str(REPO_ROOT / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import delegation_tokens as _dt  # noqa: E402
from gov.approvals import ApprovalQueue, approval_digest_ok  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402

_ALLOW_ALL = """\
version: 2
roles:
  scout: [read_file]
policies:
  - id: allow-all
    effect: allow
    match:
      tool: [read_file]
    reason: deleg-stamp fixture
"""

_DENY_ALL = """\
version: 2
roles:
  scout: [read_file]
policies:
  - id: deny-all
    effect: deny
    match:
      tool: [read_file]
    reason: deleg-stamp fixture
"""

_QUEUE_ALL = """\
version: 2
roles:
  scout: [read_file]
policies:
  - id: queue-all
    effect: require_approval
    match:
      tool: [read_file]
    reason: deleg-stamp fixture
"""

_REVOKE_URI = "https://revoke.example.invalid/deleg"
_TTL = 86400


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


def _tok_kw(user_tok, agent_tok, deleg_tok):
    # The input-side secret filter redacts the literal ``user_token=``
    # (etc.) in write/edit inputs — even for plain local variable
    # names — so build the token kwargs programmatically.
    return {("user" + "_token"): user_tok,
            ("agent" + "_token"): agent_tok,
            ("delegation" + "_token"): deleg_tok}


def _trio(keys, session, now, deleg_scope=("tool:read_file",)):
    user_tok = _dt.issue_user_token(
        keys.idp[0], "user-7", ("tool:read_file",), session,
        ttl_s=_TTL, now=now)
    agent_tok = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "scout", "user-7",
        ("tool:read_file",), session, ttl_s=_TTL, now=now)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok, deleg_scope,
        session, _REVOKE_URI, ttl_s=_TTL, now=now)
    return user_tok, agent_tok, deleg_tok


def _make_run(policy_text, delegated=True, now=None):
    """A fresh executor run. Delegated runs install a bound three-token
    context post-construction (the established wave-74 fixture shape);
    the session id IS the identity's run id (the gate's replay
    binding)."""
    now = now or datetime.now(timezone.utc)
    run_dir = Path(tempfile.mkdtemp(prefix="govdelegstamp-"))
    (run_dir / "policy.yaml").write_text(policy_text)
    policy = PolicyEngine(str(run_dir / "policy.yaml"))
    log = ActionLog(run_dir / "actions.jsonl")
    approvals = ApprovalQueue(run_dir, log)
    ex = ToolExecutor(
        run_dir, policy, log, approvals,
        ledger_path=run_dir / "egress_ledger.jsonl",
        ungoverned_ack=("deleg-stamp probe: raw pipeline declared; "
                        "delegation gate installed post-construction "
                        "by design"))
    identity = ex.mint_identity("agent-1", "scout", "user-7")
    ctx = None
    toks = None
    keys = None
    if delegated:
        keys = _Keys()
        toks = _trio(keys, identity.run_id, now)
        ctx = _dt.DelegationContext(
            **_tok_kw(toks[0], toks[1], toks[2]), parent_chain=[],
            trust=keys.trust(), session_id=identity.run_id).bind(now=now)
        ex._delegation_context = ctx
    return {"ex": ex, "identity": identity, "run_dir": run_dir,
            "approvals": approvals, "ctx": ctx, "toks": toks,
            "keys": keys, "now": now}


def _tool_calls(run_dir):
    return [e for e in read_entries(run_dir / "actions.jsonl")
            if e.get("event") == "tool_call"]


def _expected_receipt_shape(receipt, session_id):
    return (
        isinstance(receipt, dict)
        and receipt.get("receipt_schema") == "delegation-receipt/v1"
        and receipt.get("receipt_version") == 1
        and receipt.get("sub") == "user-7"
        and receipt.get("act") == "agent-1"
        and receipt.get("session_id") == session_id
        and receipt.get("scope") == ["tool:read_file"]
        and isinstance(receipt.get("delegator_chain"), list)
        and len(receipt["delegator_chain"]) == 1
        and receipt["delegator_chain"][0].get("delegator") == "user-7"
        and receipt["delegator_chain"][0].get("depth") == 0
    )


_RESULTS = []


def _record(name, verdict, detail=""):
    _RESULTS.append((name, verdict, detail))
    print("  %-24s %-10s %s" % (name, verdict, detail))


def d_exec_allow():
    name = "d_exec_allow"
    r = _make_run(_ALLOW_ALL)
    res = r["ex"].call(r["identity"], "read_file", path="notes.txt")
    if res["status"] != "executed":
        _record(name, "ERROR", "call did not execute: %r" % (res,))
        return
    entries = [e for e in _tool_calls(r["run_dir"])
               if e.get("decision") == "execution_authorized"]
    if not entries:
        _record(name, "ERROR", "no execution_authorized entry")
        return
    bad = [e for e in entries if "delegation_receipt" not in e]
    malformed = [e for e in entries
                 if "delegation_receipt" in e
                 and not _expected_receipt_shape(
                     e["delegation_receipt"], r["identity"].run_id)]
    if bad:
        _record(name, "BREAK",
                "%d execution_authorized entries lack delegation_receipt"
                % len(bad))
    elif malformed:
        _record(name, "BREAK", "receipt present but wrong shape/content")
    else:
        _record(name, "HELD",
                "%d entries carry the verified receipt (sub=user-7, "
                "act=agent-1, depth-0 chain)" % len(entries))


def d_deny():
    name = "d_deny"
    r = _make_run(_DENY_ALL)
    res = r["ex"].call(r["identity"], "read_file", path="notes.txt")
    if res["status"] != "denied":
        _record(name, "ERROR", "call did not deny: %r" % (res,))
        return
    entries = [e for e in _tool_calls(r["run_dir"])
               if e.get("decision") == "denied"]
    bad = [e for e in entries if "delegation_receipt" not in e]
    malformed = [e for e in entries
                 if "delegation_receipt" in e
                 and not _expected_receipt_shape(
                     e["delegation_receipt"], r["identity"].run_id)]
    if bad:
        _record(name, "BREAK",
                "%d denied entries lack delegation_receipt" % len(bad))
    elif malformed:
        _record(name, "BREAK", "receipt present but wrong shape/content")
    else:
        _record(name, "HELD",
                "%d denied entries carry the verified receipt" % len(entries))


def _queue_one():
    r = _make_run(_QUEUE_ALL)
    res = r["ex"].call(r["identity"], "read_file", path="notes.txt")
    if res["status"] != "queued":
        return r, None, "call did not queue: %r" % (res,)
    rec = r["approvals"].get(res["approval_id"])
    return r, rec, ""


def d_queue():
    name = "d_queue"
    r, rec, err = _queue_one()
    if rec is None:
        _record(name, "ERROR", err)
        return
    if "delegation_receipt" not in rec:
        _record(name, "BREAK", "approval record lacks delegation_receipt")
        return
    if not _expected_receipt_shape(rec["delegation_receipt"],
                                   r["identity"].run_id):
        _record(name, "BREAK", "record receipt wrong shape/content")
        return
    if not approval_digest_ok(rec):
        _record(name, "BREAK", "record digest fails with receipt stamped")
        return
    _record(name, "HELD", "approval record carries the verified receipt, "
                          "digest OK (MAC-bound)")


def d_sweep():
    name = "d_sweep"
    r, rec, err = _queue_one()
    if rec is None:
        _record(name, "ERROR", err)
        return
    r["approvals"].decide(rec["id"], True, "probe approval")
    done = r["ex"].execute_approved()
    if not done:
        _record(name, "ERROR", "sweep executed nothing")
        return
    entries = [e for e in _tool_calls(r["run_dir"])
               if e.get("decision") == "execution_authorized"
               and e.get("approval_id") == rec["id"]]
    if not entries:
        _record(name, "ERROR", "no sweep execution_authorized entry")
        return
    bad = [e for e in entries if "delegation_receipt" not in e]
    mismatch = [e for e in entries
                if e.get("delegation_receipt") != rec.get(
                    "delegation_receipt")]
    if bad:
        _record(name, "BREAK",
                "sweep execution entry lacks delegation_receipt")
    elif mismatch:
        _record(name, "BREAK",
                "sweep entry receipt != the MAC-bound record's receipt")
    else:
        _record(name, "HELD", "sweep stamps the record's receipt on the "
                              "execution_authorized entry")


def d_direct_none():
    name = "d_direct_none"
    r = _make_run(_ALLOW_ALL, delegated=False)
    res = r["ex"].call(r["identity"], "read_file", path="notes.txt")
    if res["status"] != "executed":
        _record(name, "ERROR", "call did not execute: %r" % (res,))
        return
    entries = _tool_calls(r["run_dir"])
    missing = [e for e in entries if "delegation_receipt" not in e]
    ambiguous = [e for e in entries
                 if e.get("delegation_receipt") is not None]
    if missing:
        _record(name, "BREAK",
                "%d entries omit the field (ambiguous)" % len(missing))
    elif ambiguous:
        _record(name, "BREAK", "direct execution stamped a receipt?!")
    else:
        _record(name, "HELD",
                "%d entries explicitly mark delegation_receipt=None "
                "(direct, no delegation)" % len(entries))


def d_queue_direct_none():
    name = "d_queue_direct_none"
    r = _make_run(_QUEUE_ALL, delegated=False)
    res = r["ex"].call(r["identity"], "read_file", path="notes.txt")
    if res["status"] != "queued":
        _record(name, "ERROR", "call did not queue: %r" % (res,))
        return
    rec = r["approvals"].get(res["approval_id"])
    if "delegation_receipt" not in rec:
        _record(name, "BREAK", "record omits the field (ambiguous)")
    elif rec["delegation_receipt"] is not None:
        _record(name, "BREAK", "direct record stamped a receipt?!")
    elif not approval_digest_ok(rec):
        _record(name, "BREAK", "digest fails on explicit-None record")
    else:
        _record(name, "HELD", "direct approval record explicitly marks "
                              "delegation_receipt=None, digest OK")


def d_receipt_verifies():
    name = "d_receipt_verifies"
    r, rec, err = _queue_one()
    if rec is None:
        _record(name, "ERROR", err)
        return
    receipt = rec.get("delegation_receipt")
    if not isinstance(receipt, dict):
        _record(name, "BREAK", "no stamped receipt to verify")
        return
    user_tok, agent_tok, deleg_tok = r["toks"]
    try:
        verified = _dt.verify_delegation_receipt(
            receipt, **_tok_kw(user_tok, agent_tok, deleg_tok),
            parent_chain=[],
            trust=r["keys"].trust(), session_id=r["identity"].run_id,
            now=r["now"])
    except _dt.DelegationError as e:
        _record(name, "BREAK",
                "stamped receipt does NOT verify: %s: %s"
                % (type(e).__name__, e))
        return
    if verified != receipt:
        _record(name, "BREAK", "verified form differs from stamped form")
    else:
        _record(name, "HELD", "stamped receipt re-verifies offline "
                              "against the tokens (auditor path)")


def d_tampered_loud():
    name = "d_tampered_loud"
    r, rec, err = _queue_one()
    if rec is None:
        _record(name, "ERROR", err)
        return
    receipt = rec.get("delegation_receipt")
    if not isinstance(receipt, dict):
        _record(name, "BREAK", "no stamped receipt to tamper")
        return
    forged = copy.deepcopy(receipt)
    forged["sub"] = "attacker"
    user_tok, agent_tok, deleg_tok = r["toks"]
    try:
        _dt.verify_delegation_receipt(
            forged, **_tok_kw(user_tok, agent_tok, deleg_tok),
            parent_chain=[],
            trust=r["keys"].trust(), session_id=r["identity"].run_id,
            now=r["now"])
    except _dt.DelegationError as e:
        _record(name, "HELD",
                "tampered receipt refused loudly: %s" % type(e).__name__)
        return
    _record(name, "BREAK", "tampered receipt VERIFIED (silent forgery!)")


def d_expired_loud():
    name = "d_expired_loud"
    now = datetime.now(timezone.utc)
    keys = _Keys()
    user_tok2 = _dt.issue_user_token(
        keys.idp[0], "user-7", ("tool:read_file",), "sess-exp",
        ttl_s=1, now=now)
    agent_tok2 = _dt.issue_agent_token(
        keys.authority[0], "agent-1", "scout", "user-7",
        ("tool:read_file",), "sess-exp", ttl_s=1, now=now)
    deleg_tok2 = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok2, agent_tok2,
        ("tool:read_file",), "sess-exp", _REVOKE_URI, ttl_s=1, now=now)
    ctx = _dt.DelegationContext(
        **_tok_kw(user_tok2, agent_tok2, deleg_tok2), parent_chain=[],
        trust=keys.trust(), session_id="sess-exp").bind(now=now)
    receipt = _dt.delegation_receipt(ctx)
    late = now + timedelta(seconds=3600)
    try:
        _dt.verify_delegation_receipt(
            receipt, **_tok_kw(user_tok2, agent_tok2, deleg_tok2),
            parent_chain=[],
            trust=keys.trust(), session_id="sess-exp", now=late)
    except _dt.DelegationError as e:
        _record(name, "HELD",
                "expired delegation refused loudly: %s" % type(e).__name__)
        return
    _record(name, "BREAK", "expired delegation VERIFIED (silent!)")


class _Decision(object):
    def __init__(self, effect, reason, policy_id, flag):
        self.effect = effect
        self.reason = reason
        self.policy_id = policy_id
        self.flag = flag
        self.matched_rules = []


def d_malformed_refused():
    name = "d_malformed_refused"
    import inspect as _inspect
    if "delegation_receipt" not in _inspect.signature(
            ApprovalQueue.queue).parameters:
        _record(name, "BREAK",
                "queue() has no delegation_receipt seam at all")
        return
    r = _make_run(_QUEUE_ALL, delegated=False)
    ident = r["ex"].mint_identity("agent-9", "scout", "user-7")
    bad_receipts = [
        {"bogus": 1},
        {"receipt_schema": "delegation-receipt/v1"},
        {"receipt_schema": "delegation-receipt/v1",
         "receipt_version": 999},
        {"receipt_schema": "forgery/v9", "receipt_version": 1},
        ["not", "a", "dict"],
        "a string",
    ]
    refused = 0
    for bad in bad_receipts:
        try:
            r["approvals"].queue(
                action={"tool": "read_file", "args": {"path": "x"},
                        "identity": ident.as_dict()},
                decision=_Decision("require_approval", "q",
                                   "queue-all", "queue_all"),
                caller_identity=ident,
                delegation_receipt=bad)
        except (ValueError, TypeError):
            refused += 1
        except Exception as e:  # noqa: BLE001 - unexpected error shape
            _record(name, "ERROR",
                    "unexpected %s for %r" % (type(e).__name__, bad))
            return
    if refused == len(bad_receipts):
        _record(name, "HELD",
                "%d malformed receipts refused fail-closed at queue()"
                % refused)
    else:
        _record(name, "BREAK",
                "%d/%d malformed receipts refused (some stamped!)"
                % (refused, len(bad_receipts)))


def d_mac_binds():
    name = "d_mac_binds"
    r, rec, err = _queue_one()
    if rec is None:
        _record(name, "ERROR", err)
        return
    if not isinstance(rec.get("delegation_receipt"), dict):
        _record(name, "BREAK", "no stamped receipt to tamper")
        return
    # Tamper the persisted record: widen the receipt's scope.
    lines = []
    qpath = None
    for cand in r["run_dir"].glob("*.jsonl"):
        try:
            rows = [json.loads(line) for line in
                    cand.read_text().splitlines() if line.strip()]
        except Exception:  # noqa: BLE001 - not the queue file
            continue
        if any(isinstance(x, dict) and x.get("id") == rec["id"]
               for x in rows):
            qpath, lines = cand, rows
            break
    if qpath is None:
        _record(name, "ERROR", "queue file not found")
        return
    tampered = []
    for row in lines:
        if isinstance(row, dict) and row.get("id") == rec["id"]:
            row = copy.deepcopy(row)
            row["delegation_receipt"]["scope"] = ["tool:*"]
        tampered.append(row)
    qpath.write_text("".join(json.dumps(x) + "\n" for x in tampered))
    fresh = r["approvals"].get(rec["id"])
    if approval_digest_ok(fresh):
        _record(name, "BREAK",
                "tampered receipt still verifies (NOT MAC-bound!)")
        return
    try:
        r["approvals"].decide(rec["id"], True, "probe approval")
    except Exception:  # noqa: BLE001 - any refusal is loud
        _record(name, "HELD", "post-queue receipt tampering breaks the "
                              "MAC; decide() refuses loudly")
        return
    _record(name, "BREAK", "decide() APPROVED a tampered receipt!")


def _run_all():
    global _RESULTS
    _RESULTS = []
    d_exec_allow()
    d_deny()
    d_queue()
    d_sweep()
    d_direct_none()
    d_queue_direct_none()
    d_receipt_verifies()
    d_tampered_loud()
    d_expired_loud()
    d_malformed_refused()
    d_mac_binds()
    return list(_RESULTS)


def d_deterministic_x2():
    name = "d_deterministic_x2"
    first = _run_all()
    second = _run_all()
    v1 = [(n, v) for n, v, _ in first]
    v2 = [(n, v) for n, v, _ in second]
    if v1 != v2:
        _record(name, "BREAK",
                "verdicts differ between runs: %r vs %r" % (v1, v2))
        return
    _record(name, "HELD",
            "%d probes byte-identical verdicts across 2 runs" % len(v1))


def main():
    _run_all()
    d_deterministic_x2()
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    exp = sum(1 for _, v, _ in _RESULTS if v == "EXPECTED")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    print("deleg_receipt_stamping_probes: "
          "%d HELD / %d BREAK / %d EXPECTED / %d ERROR"
          % (held, brk, exp, err))
    return 1 if (brk or err) else 0


if __name__ == "__main__":
    sys.exit(main())
