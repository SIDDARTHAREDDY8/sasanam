"""Wave-297 independent red-team battery: wave-296 additions under attack.

Targets: gov/decision_trace.py (trace emission, forgery/replay-mismatch
boundary, fold rule, snapshot binding), gov/coordination_lease.py
(overlap adjacency, renew-steals-queued, grant-list retention, fencing),
gov/invocation_pipeline.py (filter fingerprinting, drift digest,
budget reserve/reconcile/release, attribution, audit deep copy).

Base: wave-296 merge 5fd40f0133918de1b881440d7da1aad857462d5f
(verified via git rev-parse HEAD before work).

Pin 1753 (no new codes minted by this lane -- attack only; gov/ stays
byte-identical). Next free F371.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g297-rt && TMPDIR=/var/tmp/g297-rt \
    ~/workspace/.gov-venv/bin/python evals/w297_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g297-rtb \
    ~/workspace/.gov-venv/bin/python evals/w297_redteam_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import json
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import decision_trace as dt
from gov import coordination_lease as cl
from gov import invocation_pipeline as ip
from gov import decision_codes as dc
import gov.tool_call_policy as tcp

TAXONOMY_PIN = 1916 # Wave-296 merge pin; this lane mints no codes.; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 4: pin 1820 -> 1822 (+2 workflow-saga-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*)

_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_coded(name, fn, codes):
    """fn must raise a coded error whose .code is in codes. Anything
    else (no raise, uncoded raise, wrong code) is a BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code in codes:
            return _record(name, "HELD", "coded %s" % (code,))
        return _record(name, "BREAK",
                       "wrong escape: %s(code=%r), want one of %s"
                       % (type(e).__name__, code, sorted(codes)))
    return _record(name, "BREAK", "no refusal: fn returned")


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


class _Seed:
    SEED = bytes(range(32))


def _tracer(version="p1"):
    return dt.DecisionTracer(_Seed.SEED, version)


def _good_envelope(tracer=None, edges=None, verdict="DENY"):
    tracer = tracer or _tracer()
    edges = edges if edges is not None else [
        {"seq": 0, "layer": "l", "rule": "r", "outcome": "pass"},
        {"seq": 1, "layer": "l", "rule": "r2", "outcome": "deny",
         "reason": "x"}]
    return tracer.emit("d1", "snap1", edges, {"a": 1}, verdict)


# ---------------------------------------------------------------------------
# decision_trace
# ---------------------------------------------------------------------------

class DecisionTraceAttackTest(unittest.TestCase):
    def test_footer_state_matches_wave297(self):
        # Wave-297's own red team filed F371 (LOW, OPEN) after the
        # base-state probe ran; wave-298 lane 1 CLOSED it, and the
        # wave-298 red team filed F372/F373 (LOW, OPEN). Wave-299 lane 1
        # CLOSED F372/F373; the wave-299 red team filed F374/F375/F376
        # (OPEN). Wave-300 lanes 1-2 CLOSED F374/F375/F376; the wave-300
        # red team filed F377/F378 (OPEN). The footer must say so in its
        # own words. (Merge re-pin, wave-301: F377/F378 CLOSED by lanes
        # 1-2; F379 filed OPEN by the wave-301 red team. Re-pin, wave-302
        # lane 1: F379 CLOSED. Merged footer: open findings: none /
        # next free F380.)
        path = os.path.join(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))), "evals",
            "FINDINGS.md")
        # Wave-304 lane A re-pin: F385 CLOSED by this lane. The old
        # windowed-substring form (read()[-4000:]) could no longer see
        # the footer line (~6000 chars from EOF as the history chain
        # grows), so this anchors to the LAST footer matches in the
        # full file, like the w299+ batteries.
        text = open(path, encoding="utf-8").read()
        m_open = _re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = _re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        ok = (m_open and m_open[-1].strip() == "F394"
              and m_next and m_next[-1] == "F395")
        self.assertTrue(_expect_held("footer-state", ok,
                                    "footer disagrees") == "HELD")

    def test_pin_taxonomy(self):
        codes = _re.findall(r'''['"]code['"]\s*:\s*['"]([^'"]+)['"]''',
                            open(_decision_codes_path()).read())
        ok = len(codes) == TAXONOMY_PIN and len(set(codes)) == TAXONOMY_PIN \
            and codes == sorted(codes) and \
            len(dc.TAXONOMY) == TAXONOMY_PIN
        self.assertTrue(_expect_held("pin-1753", ok,
                                    "taxonomy pin mismatch") == "HELD")

    def test_dropped_edge_forgery(self):
        env = _good_envelope()
        env["trace"]["edges"] = env["trace"]["edges"][:1]
        _expect_coded("trace-drop-edge-forgery",
                      lambda: dt.verify_trace(env, _tracer().pubkey_hex),
                      {"decision-trace-forgery"})

    def test_reason_substitution_forgery(self):
        env = _good_envelope()
        env["trace"]["edges"][1]["reason"] = "rewritten"
        _expect_coded("trace-reason-sub-forgery",
                      lambda: dt.verify_trace(env, _tracer().pubkey_hex),
                      {"decision-trace-forgery"})

    def test_edge_reorder_forgery(self):
        env = _good_envelope(edges=[
            {"seq": 0, "layer": "l", "rule": "r", "outcome": "deny"},
            {"seq": 1, "layer": "l", "rule": "r2", "outcome": "allow"}])
        # swap the seq labels (reorder + relabel) -- signature must die
        e0, e1 = env["trace"]["edges"]
        e0["seq"], e1["seq"] = e1["seq"], e0["seq"]
        _expect_coded("trace-reorder-forgery",
                      lambda: dt.verify_trace(env, _tracer().pubkey_hex),
                      {"decision-trace-forgery"})

    def test_injected_outcome_edge_forgery(self):
        env = _good_envelope()
        env["trace"]["edges"].append(
            {"seq": 2, "layer": "l", "rule": "evil", "outcome": "allow"})
        _expect_coded("trace-inject-edge-forgery",
                      lambda: dt.verify_trace(env, _tracer().pubkey_hex),
                      {"decision-trace-forgery"})

    def test_signed_inconsistent_verdict_replay_mismatch(self):
        # sign_body is public by design; a signed body whose verdict
        # disagrees with its edges must refuse replay-mismatch.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = dict(env["trace"])
        body["final_decision"] = {"verdict": "ALLOW", "code": None}
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("trace-signed-divergence-mismatch",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-replay-mismatch"})

    def test_wrong_snapshot_token_replay_mismatch(self):
        env = _good_envelope()
        _expect_coded("trace-snapshot-moved-mismatch",
                      lambda: dt.verify_trace(
                          env, _tracer().pubkey_hex,
                          expected_snapshot_token="snap2"),
                      {"decision-trace-replay-mismatch"})

    def test_wrong_policy_version_replay_mismatch(self):
        env = _good_envelope()
        _expect_coded("trace-version-moved-mismatch",
                      lambda: dt.verify_trace(
                          env, _tracer().pubkey_hex,
                          expected_policy_version="p2"),
                      {"decision-trace-replay-mismatch"})

    def test_fold_rule_last_outcome_wins(self):
        self.assertTrue(_expect_held(
            "fold-last-outcome-wins",
            dt.fold_edges([{"seq": 0, "outcome": "allow"},
                           {"seq": 1, "outcome": "deny"}]) == "DENY"
            and dt.fold_edges([{"seq": 0, "outcome": "deny"},
                               {"seq": 1, "outcome": "allow"}]) == "ALLOW"
            and dt.fold_edges([{"seq": 0, "outcome": "would-deny"}])
            == "ALLOW") == "HELD")

    def test_fold_no_outcome_edge_fail_closed_deny(self):
        self.assertTrue(_expect_held(
            "fold-no-outcome-deny",
            dt.fold_edges([{"seq": 0, "outcome": "pass"},
                           {"seq": 1, "outcome": "no-match"}]) == "DENY")
            == "HELD")

    def test_signed_trace_missing_verdict(self):
        # F371: validly-signed trace whose final_decision lacks
        # "verdict" -- verify_trace dereferences it uncoded (KeyError).
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        del body["final_decision"]["verdict"]
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-missing-verdict",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_final_decision_not_dict(self):
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["final_decision"] = "DENY"
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-final-not-dict",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_edges_not_list(self):
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["edges"] = {"0": {}}
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-edges-not-list",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_edge_missing_seq(self):
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["edges"] = [{"outcome": "deny"}]
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-edge-missing-seq",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_edge_missing_outcome(self):
        # F371 close-when: an edge missing "outcome" post-signature
        # must refuse coded invalid (via _check_edges reuse), not
        # crash in fold_edges.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["edges"] = [{"seq": 0, "layer": "l", "rule": "r"}]
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-edge-missing-outcome",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_edge_duplicate_seq(self):
        # F371 close-when: duplicate seqs post-signature refuse coded
        # invalid via _check_edges reuse.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["edges"] = [{"seq": 0, "layer": "l", "rule": "r",
                          "outcome": "deny"},
                         {"seq": 0, "layer": "l", "rule": "r2",
                          "outcome": "pass"}]
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-edge-duplicate-seq",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_final_decision_none(self):
        # F371 close-when: final_decision None (not a dict)
        # post-signature refuses coded invalid.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["final_decision"] = None
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-final-none",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-invalid"})

    def test_signed_trace_verdict_nonstandard_diverges(self):
        # A signed trace with a well-formed but non-standard verdict
        # must refuse coded replay-mismatch (divergence), never crash.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = copy.deepcopy(env["trace"])
        body["final_decision"] = {"verdict": "MAYBE", "code": None}
        bad = {"trace": body, "signature": tracer.sign_body(body),
               "keyid": "decision-tracer"}
        _expect_coded("F371-signed-verdict-nonstandard",
                      lambda: dt.verify_trace(bad, tracer.pubkey_hex),
                      {"decision-trace-replay-mismatch"})

    def test_signed_trace_empty_edges_allow_claim(self):
        # Empty edges fold fail-closed DENY; a signed ALLOW claim on
        # empty edges must refuse coded replay-mismatch.
        tracer = _tracer()
        env = _good_envelope(tracer, edges=[], verdict="ALLOW")
        _expect_coded("F371-signed-empty-edges-allow-claim",
                      lambda: dt.verify_trace(env, tracer.pubkey_hex),
                      {"decision-trace-replay-mismatch"})

    def test_wellformed_signed_trace_still_verifies(self):
        # The fix must not break honest traces.
        tracer = _tracer()
        env = _good_envelope(tracer)
        body = dt.verify_trace(env, tracer.pubkey_hex,
                               expected_policy_version="p1",
                               expected_snapshot_token="snap1")
        self.assertTrue(_expect_held("F371-wellformed-verifies",
                                    isinstance(body, dict)) == "HELD")

    def test_malformed_pubkey_invalid(self):
        env = _good_envelope()
        _expect_coded("trace-bad-pubkey-invalid",
                      lambda: dt.verify_trace(env, "nothex"),
                      {"decision-trace-invalid"})

    def test_missing_signature_invalid(self):
        env = _good_envelope()
        del env["signature"]
        _expect_coded("trace-missing-sig-invalid",
                      lambda: dt.verify_trace(env, _tracer().pubkey_hex),
                      {"decision-trace-invalid"})

    def test_circular_inputs_digest_coded(self):
        tracer = _tracer()
        circ = {}
        circ["self"] = circ
        _expect_coded("trace-circular-inputs-invalid",
                      lambda: tracer.emit("d", "s",
                                          [{"seq": 0, "layer": "l",
                                            "rule": "r",
                                            "outcome": "deny"}],
                                          {"c": circ}, "DENY"),
                      {"decision-trace-invalid"})


# ---------------------------------------------------------------------------
# coordination_lease
# ---------------------------------------------------------------------------

_AUTH = bytes(range(1, 33))


def _mgr():
    return cl.LeaseManager()


class CoordinationLeaseAttackTest(unittest.TestCase):
    def test_adjacent_touching_grants_queue(self):
        m = _mgr()
        m.acquire("adj", 100, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        l2 = m.acquire("adj", 100, "holder-b", authority_seed=_AUTH,
                       issued_at=1100)
        self.assertTrue(_expect_held(
            "lease-adjacent-touching-queues",
            l2["fencing_token"] == 2) == "HELD")

    def test_overlapping_grant_denied(self):
        m = _mgr()
        m.acquire("ovl", 100, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        _expect_coded("lease-overlap-denied",
                      lambda: m.acquire("ovl", 100, "holder-c",
                                        authority_seed=_AUTH,
                                        issued_at=1050),
                      {"coord-lease-denied"})

    def test_zero_ttl_invalid(self):
        _expect_coded("lease-zero-ttl-invalid",
                      lambda: _mgr().acquire("z", 0, "holder-a",
                                             authority_seed=_AUTH),
                      {"coord-lease-invalid"})

    def test_renew_stealing_queued_future_denied(self):
        m = _mgr()
        m.acquire("rnw", 100, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        m.acquire("rnw", 100, "holder-b", authority_seed=_AUTH,
                  issued_at=1100)
        _expect_coded("lease-renew-steal-denied",
                      lambda: m.renew("rnw", 1, "holder-a", 500,
                                      authority_seed=_AUTH,
                                      checked_at=1050),
                      {"coord-lease-denied"})

    def test_renew_expired_refuses(self):
        m = _mgr()
        m.acquire("rxp", 10, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        _expect_coded("lease-renew-expired",
                      lambda: m.renew("rxp", 1, "holder-a", 5,
                                      authority_seed=_AUTH,
                                      checked_at=2000),
                      {"coord-lease-expired"})

    def test_zombie_write_after_reacquire_fencing(self):
        m = _mgr()
        m.acquire("zom", 10, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        m.release("zom", 1, "holder-a")
        m.acquire("zom", 100, "holder-b", authority_seed=_AUTH,
                  issued_at=3000)
        _expect_coded("lease-zombie-write-fencing",
                      lambda: m.check_write("zom", 1, "holder-a",
                                            checked_at=3050),
                      {"coord-lease-fencing"})

    def test_future_grant_does_not_evict_live(self):
        # F367 re-pin: the live lease's writes still authorize after a
        # future-dated non-overlapping grant queues.
        m = _mgr()
        m.acquire("f67", 100, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        m.acquire("f67", 100, "holder-b", authority_seed=_AUTH,
                  issued_at=1100)
        ok = m.check_write("f67", 1, "holder-a",
                           checked_at=1050) is True
        self.assertTrue(_expect_held("lease-f367-live-survives", ok)
                        == "HELD")

    def test_verify_lease_wrong_authority_invalid(self):
        m = _mgr()
        lease = m.acquire("vrf", 100, "holder-a", authority_seed=_AUTH,
                          issued_at=1000)
        other = bytes(range(2, 34))
        from gov import ed25519
        _expect_coded("lease-wrong-authority-invalid",
                      lambda: cl.verify_lease(
                          lease, ed25519.publickey(other).hex(),
                          checked_at=1050),
                      {"coord-lease-invalid"})

    def test_verify_lease_expired(self):
        m = _mgr()
        lease = m.acquire("vxp", 10, "holder-a", authority_seed=_AUTH,
                          issued_at=1000)
        from gov import ed25519
        _expect_coded("lease-verify-expired",
                      lambda: cl.verify_lease(
                          lease, ed25519.publickey(_AUTH).hex(),
                          checked_at=2000),
                      {"coord-lease-expired"})

    def test_release_unknown_token_fencing(self):
        m = _mgr()
        m.acquire("rel", 100, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        _expect_coded("lease-release-unknown-fencing",
                      lambda: m.release("rel", 99, "holder-a"),
                      {"coord-lease-fencing"})

    def test_grant_list_retention_lineage(self):
        # F367: grants are retained, never evicted by a later grant.
        m = _mgr()
        m.acquire("lin", 10, "holder-a", authority_seed=_AUTH,
                  issued_at=1000)
        m.acquire("lin", 10, "holder-b", authority_seed=_AUTH,
                  issued_at=2000)
        self.assertTrue(_expect_held(
            "lease-grants-retained",
            len(m._leases["lin"]) == 2) == "HELD")


# ---------------------------------------------------------------------------
# invocation_pipeline
# ---------------------------------------------------------------------------

def _mkctx(**kw):
    base = {"tool": "t", "session_id": "s", "call_id": "c"}
    base.update(kw)
    return ip.InvocationContext(**base)


def _same_name_fn(name, body_line):
    ns = {}
    exec("def %s(ctx, nxt):\n    %s\n    return nxt(ctx)\n"
         % (name, body_line), ns)
    return ns[name]


class InvocationPipelineAttackTest(unittest.TestCase):
    def test_identical_code_different_identity_digest_differs(self):
        f1 = _same_name_fn("flt", "pass")
        f2 = _same_name_fn("flt", "pass")
        d1 = ip._stack_digest("s", (f1,), None)
        d2 = ip._stack_digest("s", (f2,), None)
        self.assertTrue(_expect_held(
            "pipeline-identical-code-identity-differs", d1 != d2)
            == "HELD")

    def test_same_name_different_code_drift_refused(self):
        f1 = _same_name_fn("flt", "pass")
        st = ip.build_filter_stack([f1])
        st._filters = (_same_name_fn("flt", "x = 1"),)
        _expect_coded("pipeline-F368-drift-frozen",
                      lambda: st.invoke(lambda ctx: "ok", _mkctx()),
                      {"toolcall-filter-frozen"})

    def test_audit_log_deep_copy(self):
        # F369 re-pin: mutating a returned record cannot touch storage.
        st = ip.default_stack()
        st.invoke(lambda ctx: {"api_key": "sk-abcdefghijklmnop"},
                  _mkctx())
        got = st.audit_log()
        n = len(got[0]["record"]["redactions"])
        got[0]["record"]["redactions"].append("$.evil")
        self.assertTrue(_expect_held(
            "pipeline-F369-deep-copy",
            len(st.audit_log()[0]["record"]["redactions"]) == n)
            == "HELD")

    def test_denial_still_logged(self):
        def denyf(ctx, nxt):
            raise ip.InvocationPipelineError("no", code=ip.INVALID_CALL)
        af = ip.make_audit_filter()
        st = ip.FilterStack([af, denyf])
        try:
            st.invoke(lambda ctx: "ok", _mkctx())
        except ip.InvocationPipelineError:
            pass
        self.assertTrue(_expect_held(
            "pipeline-denial-logged",
            af.log[0]["record"]["outcome"] == "denied"
            and af.log[0]["record"]["code"] == ip.INVALID_CALL)
            == "HELD")

    def test_budget_reservation_released_on_deny(self):
        def denyf(ctx, nxt):
            raise ip.InvocationPipelineError("no", code=ip.INVALID_CALL)
        ledger = ip.BudgetLedger()
        ledger.declare_scope("alice", 10.0, window_seconds=60)
        st = ip.FilterStack([ip.make_budget_filter(ledger), denyf])
        try:
            st.invoke(lambda ctx: "ok",
                      _mkctx(caller={"identity": "alice"},
                             declared_cost=5.0))
        except ip.InvocationPipelineError:
            pass
        self.assertTrue(_expect_held(
            "pipeline-budget-no-leak",
            ledger.state("alice")["outstanding"] == 0.0) == "HELD")

    def test_double_reconcile_refuses(self):
        ledger = ip.BudgetLedger()
        ledger.declare_scope("bob", 10.0, window_seconds=60)
        tok = ledger.reserve("bob", "call-1", 2.0)
        ledger.reconcile(tok, 1.0)
        _expect_coded("pipeline-double-reconcile",
                      lambda: ledger.reconcile(tok, 1.0),
                      {"toolcall-budget-reserve-invalid"})

    def test_non_bytes_signer_loud(self):
        af = ip.make_audit_filter(signer=lambda b: "not-bytes")
        st = ip.FilterStack([af])
        _expect_coded("pipeline-nonbytes-signer",
                      lambda: st.invoke(lambda ctx: "ok", _mkctx()),
                      {"toolfilter-skip-denied"})

    def test_filter_own_crash_wrapped(self):
        def crashf(ctx, nxt):
            raise RuntimeError("own crash")
        st = ip.FilterStack([crashf])
        _expect_coded("pipeline-own-crash-wrapped",
                      lambda: st.invoke(lambda ctx: "ok", _mkctx()),
                      {"toolfilter-skip-denied"})

    def test_inner_coded_refusal_propagates_unchanged(self):
        def denyf(ctx, nxt):
            raise ip.InvocationPipelineError("no", code=ip.INVALID_CALL)
        st = ip.FilterStack([lambda ctx, nxt: nxt(ctx), denyf])
        _expect_coded("pipeline-inner-coded-unchanged",
                      lambda: st.invoke(lambda ctx: "ok", _mkctx()),
                      {"toolcall-invalid-call"})

    def test_skip_without_next_denied(self):
        st = ip.FilterStack([lambda ctx, nxt: "swallowed"])
        _expect_coded("pipeline-skip-denied",
                      lambda: st.invoke(lambda ctx: "ok", _mkctx()),
                      {"toolfilter-skip-denied"})

    def test_double_next_denied(self):
        def doublenext(ctx, nxt):
            nxt(ctx)
            return nxt(ctx)
        st = ip.FilterStack([doublenext])
        _expect_coded("pipeline-double-next-denied",
                      lambda: st.invoke(lambda ctx: "ok", _mkctx()),
                      {"toolfilter-skip-denied"})

    def test_add_filter_frozen(self):
        st = ip.build_filter_stack([lambda ctx, nxt: nxt(ctx)])
        _expect_coded("pipeline-add-frozen",
                      lambda: st.add_filter(lambda ctx, nxt: nxt(ctx)),
                      {"toolcall-filter-frozen"})

    def test_body_crash_propagates_and_logs_crashed(self):
        af = ip.make_audit_filter()
        st = ip.FilterStack([af])
        try:
            st.invoke(lambda ctx: (_ for _ in ()).throw(
                RuntimeError("body blew up")), _mkctx())
            ok = False
        except RuntimeError:
            ok = af.log[0]["record"]["outcome"] == "crashed"
        self.assertTrue(_expect_held("pipeline-body-crash-logged", ok)
                        == "HELD")

    def test_secret_redaction_records_paths(self):
        st = ip.default_stack()
        result = st.invoke(lambda ctx: {"api_key": "sk-abcdefghijklmnop"},
                           _mkctx())
        self.assertTrue(_expect_held(
            "pipeline-secret-redacted",
            result == {"api_key": "[REDACTED]"}
            and "$.api_key" in st.audit_log()[0]["record"]["redactions"])
            == "HELD")


# ---------------------------------------------------------------------------
# emission wiring (tool_call_policy x decision_trace)
# ---------------------------------------------------------------------------

def _policy_doc(rules, mode="enforce"):
    return {"format": "sasanam-tool-call-policy/v1", "name": "unit-policy",
            "selector": {"agents": ["agent-a"]}, "mode": mode,
            "rules": rules}


def _caller(ident="agent-a"):
    return {"identity": ident, "authenticated": True, "tags": []}


class EmissionWiringTest(unittest.TestCase):
    def _policy(self, tracer):
        pol = tcp.CompiledToolPolicy(_policy_doc(
            [{"tool": "read_file", "operation": "read", "action": "ALLOW",
              "severity": 3, "message": "ok"}]))
        pol.bind_tracer(tracer)
        return pol

    def test_allow_decision_carries_verifying_trace(self):
        tracer = _tracer()
        pol = self._policy(tracer)
        d = pol.decide(_caller(), "read_file", "read", args={"p": "/x"})
        env = getattr(d, "trace", None)
        ok = env is not None
        if ok:
            body = dt.verify_trace(env, tracer.pubkey_hex,
                                   expected_policy_version="p1",
                                   expected_snapshot_token=pol.digest)
            ok = body["snapshot_token"] == pol.digest
        self.assertTrue(_expect_held("emit-allow-trace-verifies", ok)
                        == "HELD")

    def test_deny_decision_carries_verifying_trace(self):
        tracer = _tracer()
        pol = self._policy(tracer)
        d = pol.decide(_caller(), "write_file", "write", args={})
        env = getattr(d, "trace", None)
        ok = env is not None and d.verdict == "DENY"
        if ok:
            dt.verify_trace(env, tracer.pubkey_hex,
                            expected_policy_version="p1",
                            expected_snapshot_token=pol.digest)
        self.assertTrue(_expect_held("emit-deny-trace-verifies", ok)
                        == "HELD")

    def test_authn_raise_emits_no_trace_by_design(self):
        tracer = _tracer()
        pol = self._policy(tracer)
        try:
            pol.decide({"identity": "agent-a", "authenticated": False,
                        "tags": []}, "read_file", "read")
            ok = False
        except tcp.ToolCallPolicyError as e:
            ok = e.code == "toolcall-unauthenticated-caller"
        self.assertTrue(_expect_held("emit-authn-raise-no-trace", ok)
                        == "HELD")

    def test_broken_tracer_never_breaks_decision(self):
        class BadTracer(dt.DecisionTracer):
            def emit(self, *a, **k):
                raise RuntimeError("tracer broken")
        pol = self._policy(BadTracer(_Seed.SEED, "p1"))
        d = pol.decide(_caller(), "read_file", "read", args={})
        ok = d.verdict == "ALLOW" and not getattr(d, "trace", None)
        self.assertTrue(_expect_held("emit-broken-tracer-swallowed", ok)
                        == "HELD")


import re as _re  # noqa: E402


def _decision_codes_path():
    return os.path.join(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))), "gov",
        "decision_codes.py")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (DecisionTraceAttackTest, CoordinationLeaseAttackTest,
                InvocationPipelineAttackTest, EmissionWiringTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    errors = len(result.errors) + len(result.failures)
    brk = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    print("\n==== w297 redteam: %d BREAK / %d HELD / %d ERROR ===="
          % (len(brk), len(held), errors))
    for name, status, detail in _results:
        if status != "HELD":
            print("  %s %s: %s" % (status, name, detail))
    return 1 if (brk or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
