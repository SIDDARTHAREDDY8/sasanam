"""Wave-280 lane 3 red-first battery: ephemeral grants (OpenFGA pattern STEAL).

Gap (base 7849c86): the three-token delegation grant is a *standing*
grant for its whole TTL. Nothing attenuates it per invocation: a grant
for "call tool T once with argument digest D" authorizes tool T with ANY
arguments; a single-use delegation is re-presentable; verdicts carry no
resolution tree.

Red-first: on base every probe BREAKs (gov.ephemeral_grants absent).
After the fix: contextual tuples are a genuine enforcement input
(omission/mismatch/expiry refuse coded), single-use leases are
single-use, decisions carry expand trees, and the taxonomy pin is 1569.

Pattern lineage: openfga/openfga contextual tuples + conditions +
BatchCheck + Expand (Apache-2.0 -- mechanism only, no OpenFGA code
vendored, no Go sidecar).
"""

import hashlib
import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-fga")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 1976 # Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*).; Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_evidence(probe_id):
    try:
        from gov import ephemeral_grants as eg
        return eg
    except ImportError:
        _record(probe_id, "BREAK", "gov.ephemeral_grants absent on base")
        return None


def _hex64(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


_NOW = 1790907600.0


# -- probes ---------------------------------------------------------------

def p_module_present():
    eg = _needs_evidence("p_module_present")
    if eg is None:
        return
    _record("p_module_present", "HELD", "gov.ephemeral_grants present")


def p_tuple_omission_refused():
    eg = _needs_evidence("p_tuple_omission_refused")
    if eg is None:
        return
    d = eg.check_grant(principal="agent:alice", action="tool:db_query",
                       tuples=[], check_conditions={"now": _NOW})
    if not d["allowed"] and d["code"] == "delegation-ephemeral-grant-refused":
        _record("p_tuple_omission_refused", "HELD",
                "no tuple -> coded refusal, not silent pass")
    else:
        _record("p_tuple_omission_refused", "BREAK",
                "tuple omission not fail-closed: %r" % (d,))


def p_arg_digest_match():
    eg = _needs_evidence("p_arg_digest_match")
    if eg is None:
        return
    digest = _hex64("limit=10")
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                           obj="tool:db_query",
                           conditions={"arg_digest": digest})
    d = eg.check_grant(principal="agent:alice", action="tool:db_query",
                       tuples=[t],
                       check_conditions={"now": _NOW,
                                         "args_digest": digest})
    if d["allowed"]:
        _record("p_arg_digest_match", "HELD", "matching digest allowed")
    else:
        _record("p_arg_digest_match", "BREAK", "matching digest refused: %r" % (d,))


def p_arg_digest_mismatch():
    eg = _needs_evidence("p_arg_digest_mismatch")
    if eg is None:
        return
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                           obj="tool:db_query",
                           conditions={"arg_digest": _hex64("limit=10")})
    d = eg.check_grant(principal="agent:alice", action="tool:db_query",
                       tuples=[t],
                       check_conditions={"now": _NOW,
                                         "args_digest": _hex64("limit=9999")})
    if not d["allowed"] and d["code"] == "delegation-ephemeral-grant-refused":
        _record("p_arg_digest_mismatch", "HELD",
                "argument substitution refused coded")
    else:
        _record("p_arg_digest_mismatch", "BREAK",
                "argument substitution not refused: %r" % (d,))


def p_expired_tuple():
    eg = _needs_evidence("p_expired_tuple")
    if eg is None:
        return
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                           obj="tool:db_query",
                           conditions={"valid_until": _NOW - 60.0})
    d = eg.check_grant(principal="agent:alice", action="tool:db_query",
                       tuples=[t], check_conditions={"now": _NOW})
    if not d["allowed"]:
        _record("p_expired_tuple", "HELD", "expired tuple refused (replay)")
    else:
        _record("p_expired_tuple", "BREAK", "expired tuple allowed: replay")


def p_budget_cap():
    eg = _needs_evidence("p_budget_cap")
    if eg is None:
        return
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                           obj="tool:db_query",
                           conditions={"max_budget": 5.0})
    d = eg.check_grant(principal="agent:alice", action="tool:db_query",
                       tuples=[t],
                       check_conditions={"now": _NOW, "budget": 50.0})
    if not d["allowed"]:
        _record("p_budget_cap", "HELD", "budget overrun refused")
    else:
        _record("p_budget_cap", "BREAK", "budget overrun allowed")


def p_malformed_conditions_fail_fast():
    eg = _needs_evidence("p_malformed_conditions_fail_fast")
    if eg is None:
        return
    bad = 0
    for cond in ({"arg_digest": "not-hex"},
                 {"arg_digest": "A" * 64},
                 {"max_budget": float("nan")},
                 {"valid_until": float("inf")},
                 {"no_such_condition": 1}):
        try:
            eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                               obj="tool:db_query", conditions=cond)
        except (ValueError, TypeError):
            bad += 1
    if bad == 5:
        _record("p_malformed_conditions_fail_fast", "HELD",
                "all 5 hostile condition shapes refused at construction")
    else:
        _record("p_malformed_conditions_fail_fast", "BREAK",
                "only %d/5 hostile shapes refused" % bad)


def p_readonly_no_consequential():
    eg = _needs_evidence("p_readonly_no_consequential")
    if eg is None:
        return
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke_readonly",
                           obj="tool:db_query")
    d_write = eg.check_grant(principal="agent:alice", action="tool:db_query",
                             tuples=[t], check_conditions={"now": _NOW},
                             consequential=True)
    d_read = eg.check_grant(principal="agent:alice", action="tool:db_query",
                            tuples=[t], check_conditions={"now": _NOW},
                            consequential=False)
    if not d_write["allowed"] and d_read["allowed"]:
        _record("p_readonly_no_consequential", "HELD",
                "readonly tuple authorizes reads, refuses writes")
    else:
        _record("p_readonly_no_consequential", "BREAK",
                "readonly/consequential conflated: %r %r" % (d_write, d_read))


def p_delegated_to_chain():
    eg = _needs_evidence("p_delegated_to_chain")
    if eg is None:
        return
    t1 = eg.ContextualTuple(user="agent:alice", relation="delegated_to",
                            obj="session:s1")
    t2 = eg.ContextualTuple(user="session:s1", relation="can_invoke",
                            obj="tool:db_query")
    d = eg.check_grant(principal="agent:alice", action="tool:db_query",
                       tuples=[t1, t2], check_conditions={"now": _NOW})
    if d["allowed"]:
        _record("p_delegated_to_chain", "HELD",
                "delegation chain resolved through session userset")
    else:
        _record("p_delegated_to_chain", "BREAK",
                "userset traversal failed: %r" % (d,))


def _single_use_ctx():
    from gov import delegation_tokens as dt
    human_signer, human_pub = dt.generate_test_keypair()
    auth_signer, auth_pub = dt.generate_test_keypair()
    trust = dt.DelegationTrust(
        human_keys={human_signer.key_id: human_pub},
        authority_keys={auth_signer.key_id: auth_pub},
        user_issuer_keys={human_signer.key_id: human_pub})
    user_tok = dt.issue_user_token(human_signer, "u1", ["tool:db_query"],
                                   "sess-1")
    agent_tok = dt.issue_agent_token(auth_signer, "alice", "worker",
                                     "alice", ["tool:db_query"], "sess-1")
    dlg_tok = dt.issue_delegation(human_signer, "u1", user_tok, agent_tok,
                                  ["tool:db_query"], "sess-1",
                                  "https://revoke.example/ledger",
                                  lease="single-use")
    ctx = dt.DelegationContext(user_token=user_tok, agent_token=agent_tok,
                               delegation_token=dlg_tok, parent_chain=[],
                               trust=trust, session_id="sess-1")
    ctx.bind()
    return dt, ctx


def p_single_use_requires_tuples():
    eg = _needs_evidence("p_single_use_requires_tuples")
    if eg is None:
        return
    dt, ctx = _single_use_ctx()
    try:
        dt.authorize_action(ctx, "tool:db_query")
    except eg.EphemeralGrantError as e:
        if e.code == "delegation-ephemeral-grant-refused":
            _record("p_single_use_requires_tuples", "HELD",
                    "single-use lease without tuples: coded refusal")
            return
    except Exception as e:  # noqa: BLE001
        _record("p_single_use_requires_tuples", "BREAK",
                "wrong exception type: %r" % (e,))
        return
    _record("p_single_use_requires_tuples", "BREAK",
            "single-use lease usable without contextual tuples")


def p_single_use_spent():
    eg = _needs_evidence("p_single_use_spent")
    if eg is None:
        return
    dt, ctx = _single_use_ctx()
    lease_ref = dt.token_ref(ctx.delegation_token)
    ledger = eg.SpentLeaseRegistry()
    tup = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                             obj="tool:db_query", lease_ref=lease_ref)
    conds = {"now": _NOW, "invocation_id": "inv-1"}
    v1 = dt.authorize_action(ctx, "tool:db_query",
                             contextual_tuples=[tup],
                             check_conditions=conds,
                             spent_ledger=ledger)
    conds2 = {"now": _NOW, "invocation_id": "inv-2"}
    try:
        dt.authorize_action(ctx, "tool:db_query",
                            contextual_tuples=[tup],
                            check_conditions=conds2,
                            spent_ledger=ledger)
    except eg.EphemeralGrantError as e:
        if e.code == "delegation-ephemeral-grant-refused" and v1["action"] == "tool:db_query":
            _record("p_single_use_spent", "HELD",
                    "first use allowed, replay refused (spent)")
            return
    except Exception as e:  # noqa: BLE001
        _record("p_single_use_spent", "BREAK", "wrong exception: %r" % (e,))
        return
    _record("p_single_use_spent", "BREAK", "single-use lease replayed")


def p_single_use_requires_registry():
    eg = _needs_evidence("p_single_use_requires_registry")
    if eg is None:
        return
    dt, ctx = _single_use_ctx()
    lease_ref = dt.token_ref(ctx.delegation_token)
    tup = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                             obj="tool:db_query", lease_ref=lease_ref)
    # Fail closed (wave-280 review): a single-use lease with NO
    # spent-lease registry must refuse coded — without a registry the
    # single-use guarantee cannot be enforced and the lease would
    # silently degrade to multi-use.
    try:
        dt.authorize_action(ctx, "tool:db_query",
                            contextual_tuples=[tup],
                            check_conditions={"now": _NOW,
                                              "invocation_id": "inv-x"})
    except eg.EphemeralGrantError as e:
        if e.code == "delegation-ephemeral-grant-refused":
            _record("p_single_use_requires_registry", "HELD",
                    "single-use lease without registry: coded refusal")
            return
    except Exception as e:  # noqa: BLE001
        _record("p_single_use_requires_registry", "BREAK",
                "wrong exception type: %r" % (e,))
        return
    _record("p_single_use_requires_registry", "BREAK",
            "single-use lease allowed with no registry (silent multi-use)")


def p_decision_writer_emits_at_seam():
    eg = _needs_evidence("p_decision_writer_emits_at_seam")
    if eg is None:
        return
    os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
    os.environ.setdefault("GOV_LOG_KEY", "00" * 32)
    os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w280-fga-seam")
    from gov.log import ActionLog
    dt, ctx = _single_use_ctx()
    lease_ref = dt.token_ref(ctx.delegation_token)
    d = tempfile.mkdtemp(prefix="g280s_", dir=os.environ["TMPDIR"])
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    writer = eg.GrantDecisionWriter(log)
    ledger = eg.SpentLeaseRegistry()
    tup = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                             obj="tool:db_query", lease_ref=lease_ref)
    # Allowed decision recorded at the seam, before the verdict leaves.
    dt.authorize_action(ctx, "tool:db_query",
                       contextual_tuples=[tup],
                       check_conditions={"now": _NOW,
                                         "invocation_id": "inv-w1"},
                       spent_ledger=ledger,
                       decision_writer=writer)
    # Coded refusal also recorded at the seam (replay → spent).
    try:
        dt.authorize_action(ctx, "tool:db_query",
                            contextual_tuples=[tup],
                            check_conditions={"now": _NOW,
                                              "invocation_id": "inv-w2"},
                            spent_ledger=ledger,
                            decision_writer=writer)
    except eg.EphemeralGrantError:
        pass
    recs = eg.grant_decision_records(log)
    if (len(recs) == 2 and recs[0]["allowed"] is True
            and recs[1]["allowed"] is False
            and recs[1]["code"] == "delegation-ephemeral-grant-refused"):
        _record("p_decision_writer_emits_at_seam", "HELD",
                "seam recorded allow + coded refusal at decision time")
    else:
        _record("p_decision_writer_emits_at_seam", "BREAK",
                "seam did not record both decisions: %r"
                % ([r["allowed"] for r in recs],))


def p_batch_no_shortcircuit():
    eg = _needs_evidence("p_batch_no_shortcircuit")
    if eg is None:
        return
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                           obj="tool:db_query")
    checks = [
        {"principal": "agent:alice", "action": "tool:db_query"},
        {"principal": "agent:alice", "action": "tool:rm_rf"},
        {"principal": "agent:alice", "action": "tool:db_query"},
    ]
    vec = eg.batch_check(checks, [t], check_conditions={"now": _NOW})
    if len(vec) == 3 and vec[0]["allowed"] and not vec[1]["allowed"]\
            and vec[2]["allowed"]:
        _record("p_batch_no_shortcircuit", "HELD",
                "decision vector complete, no short-circuit")
    else:
        _record("p_batch_no_shortcircuit", "BREAK",
                "batch vector wrong: %r" % (vec,))


def p_expand_tree_material():
    eg = _needs_evidence("p_expand_tree_material")
    if eg is None:
        return
    t1 = eg.ContextualTuple(user="agent:alice", relation="delegated_to",
                            obj="session:s1")
    t2 = eg.ContextualTuple(user="session:s1", relation="can_invoke",
                            obj="tool:db_query")
    tree = eg.expand_decision(user="agent:alice", relation="can_invoke",
                              obj="tool:db_query", tuples=[t1, t2])
    import json as _json
    body = {k: v for k, v in tree.items() if k != "tree_digest"}
    canon = _json.dumps(body, sort_keys=True, separators=(",", ":"),
                        ensure_ascii=True, default=str).encode()
    if tree.get("matched") is True and tree.get("children")\
            and hashlib.sha256(canon).hexdigest() == tree.get("tree_digest"):
        _record("p_expand_tree_material", "HELD",
                "resolution tree with digest binding")
    else:
        _record("p_expand_tree_material", "BREAK",
                "expand tree malformed: %r" % (tree,))


def p_emit_chains_record():
    eg = _needs_evidence("p_emit_chains_record")
    if eg is None:
        return
    d = tempfile.mkdtemp(prefix="g280_", dir=os.environ["TMPDIR"])
    from gov.log import ActionLog, read_entries
    log = ActionLog(os.path.join(d, "audit.jsonl"))
    w = eg.GrantDecisionWriter(log)
    t = eg.ContextualTuple(user="agent:alice", relation="can_invoke",
                           obj="tool:db_query")
    decision = eg.check_grant(principal="agent:alice", action="tool:db_query",
                              tuples=[t], check_conditions={"now": _NOW})
    w.record(decision, principal="agent:alice")
    entries = [e for e in read_entries(log.path)
               if e.get("record_type") == eg.RECORD_TYPE]
    chained = (len(entries) == 1
               and entries[0].get("prev_grant_decision_digest") is not None
               and entries[0].get("record_digest"))
    if chained:
        _record("p_emit_chains_record", "HELD",
                "decision record hash-chained at decision time")
    else:
        _record("p_emit_chains_record", "BREAK",
                "record not chained: %r" % (entries,))


def p_taxonomy_pin():
    import re
    src = open(os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "gov", "decision_codes.py")).read()
    codes = re.findall(r'"code":\s*\'([^\']+)\'', src)
    if len(codes) != TAXONOMY_PIN or len(set(codes)) != TAXONOMY_PIN:
        return _record("p_taxonomy_pin", "BREAK",
                       "pin drift: %d raw / %d unique, want %d"
                       % (len(codes), len(set(codes)), TAXONOMY_PIN))
    _record("p_taxonomy_pin", "HELD", "taxonomy pin %d holds"
            % TAXONOMY_PIN)


def _green_checks():
    # Depth-1: adjacent suites only, never spawn another battery's main.
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    for mod in ("tests.test_decision_codes",):
        r = subprocess.run([sys.executable, "-m", "unittest", mod],
                           cwd=os.path.dirname(here), env=env,
                           capture_output=True, text=True, timeout=300)
        _record("green-check_" + mod,
                "HELD" if r.returncode == 0 else "ERROR",
                (r.stderr or r.stdout)[-200:])


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    for probe in (p_module_present, p_tuple_omission_refused,
                  p_arg_digest_match, p_arg_digest_mismatch,
                  p_expired_tuple, p_budget_cap,
                  p_malformed_conditions_fail_fast,
                  p_readonly_no_consequential, p_delegated_to_chain,
                  p_single_use_requires_tuples, p_single_use_spent,
                  p_single_use_requires_registry,
                  p_decision_writer_emits_at_seam,
                  p_batch_no_shortcircuit, p_expand_tree_material,
                  p_emit_chains_record, p_taxonomy_pin):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w280_fga: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    mism = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    return 1 if (n_break or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
