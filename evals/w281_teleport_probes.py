"""Wave-281 lane 5 red-first battery: Teleport access-request contract (ADAPT).

Gap (base b95c0e5): pending approvals live only in memory and die with the
process; there is no state-machined access-request record (PENDING ->
APPROVED | DENIED | EXPIRED with requestor/grants/reason/thresholds/
max-duration), no grant-as-reissued-identity (approved requests do not mint
ephemeral TTL-bound tool grants -- no standing capabilities), and no
decision<->evidence join-key discipline binding decisions to evidence.

Red-first: on base every probe BREAKs (gov.access_requests absent).
After the fix: state-machine refuses illegal transitions fail-closed,
expired requests cannot be decided, grants mint only from APPROVED
requests with TTL = max_duration, every transition is an HMAC-chained
access-request-event joined by join_key, and the taxonomy pin is 1569.

Pattern lineage: gravitational/teleport `api/` module contract shapes
(Apache-2.0 -- mechanism only; the AGPLv3 engine is off-limits; no
Teleport code vendored).
"""

import os
import secrets
import sys
import tempfile

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w281-teleport")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import probe_lines  # noqa: E402  (canonical probe-line form)

TAXONOMY_PIN = 1933 # Wave-281 lane 5: pin 1541 -> 1546 (+5 access-request-*).; Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*)

_RESULTS = []


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})


def _needs_evidence(probe_id):
    try:
        from gov import access_requests as ar
        return ar
    except ImportError:
        _record(probe_id, "BREAK", "gov.access_requests absent on base")
        return None


_NOW = 1790907600.0
_GRANTS = [{"tool": "tool:db_query"}]


def _new_log():
    from gov.log import ActionLog
    d = tempfile.mkdtemp(prefix="g281_", dir=os.environ.get("TMPDIR") or "/tmp")
    return ActionLog(os.path.join(d, "audit.jsonl"))


def _submit(ar, **kw):
    store = ar.AccessRequestStore()
    kw.setdefault("requestor", "agent:alice")
    kw.setdefault("grants", _GRANTS)
    kw.setdefault("reason", "need to run the nightly report")
    kw.setdefault("max_duration_s", 3600)
    kw.setdefault("now", _NOW)
    rec = ar.submit(store, **kw)
    return store, rec


# -- probes ---------------------------------------------------------------

def p_module_present():
    ar = _needs_evidence("p_module_present")
    if ar is None:
        return
    _record("p_module_present", "HELD", "gov.access_requests present")


def p_submit_requires_reason():
    ar = _needs_evidence("p_submit_requires_reason")
    if ar is None:
        return
    store = ar.AccessRequestStore()
    try:
        ar.submit(store, requestor="agent:alice", grants=_GRANTS,
                  reason="", max_duration_s=3600, now=_NOW)
    except ValueError:
        _record("p_submit_requires_reason", "HELD",
                "empty reason refused at submit (Teleport mandatory reason)")
        return
    _record("p_submit_requires_reason", "BREAK",
            "reasonless access request accepted")


def p_self_review_refused():
    ar = _needs_evidence("p_self_review_refused")
    if ar is None:
        return
    store, rec = _submit(ar)
    try:
        ar.review(store, rec["request_id"], reviewer="agent:alice",
                  approve=True, now=_NOW + 1)
    except ar.AccessRequestError as e:
        if e.code == "access-request-self-review-refused":
            _record("p_self_review_refused", "HELD",
                    "self-approval refused coded")
            return
        _record("p_self_review_refused", "BREAK",
                "wrong code: %r" % (e.code,))
        return
    _record("p_self_review_refused", "BREAK", "self-review not refused")


def p_threshold_not_bypassed():
    ar = _needs_evidence("p_threshold_not_bypassed")
    if ar is None:
        return
    store, rec = _submit(ar, approve_threshold=2)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    st = store.get(rec["request_id"])["state"]
    if st != "PENDING":
        _record("p_threshold_not_bypassed", "BREAK",
                "single approval bypassed threshold 2: %s" % st)
        return
    ar.review(store, rec["request_id"], reviewer="agent:carol",
              approve=True, now=_NOW + 2)
    st = store.get(rec["request_id"])["state"]
    if st == "APPROVED":
        _record("p_threshold_not_bypassed", "HELD",
                "threshold 2 required two distinct reviewers")
    else:
        _record("p_threshold_not_bypassed", "BREAK",
                "two approvals did not reach APPROVED: %s" % st)


def p_deny_is_terminal():
    ar = _needs_evidence("p_deny_is_terminal")
    if ar is None:
        return
    store, rec = _submit(ar)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=False, now=_NOW + 1)
    if store.get(rec["request_id"])["state"] != "DENIED":
        _record("p_deny_is_terminal", "BREAK", "deny did not decide DENIED")
        return
    try:
        ar.review(store, rec["request_id"], reviewer="agent:carol",
                  approve=True, now=_NOW + 2)
    except ar.AccessRequestError as e:
        if e.code == "access-request-terminal-refused":
            _record("p_deny_is_terminal", "HELD",
                    "decide-after-deny refused coded")
            return
    _record("p_deny_is_terminal", "BREAK", "decide-after-deny not refused")


def p_expired_decide_refused():
    ar = _needs_evidence("p_expired_decide_refused")
    if ar is None:
        return
    store, rec = _submit(ar, max_duration_s=100)
    try:
        ar.review(store, rec["request_id"], reviewer="agent:bob",
                  approve=True, now=_NOW + 1000)
    except ar.AccessRequestError as e:
        if e.code == "access-request-terminal-refused" and\
                store.get(rec["request_id"])["state"] == "EXPIRED":
            _record("p_expired_decide_refused", "HELD",
                    "expired request transitioned EXPIRED at read time; "
                    "late review refused coded")
            return
        _record("p_expired_decide_refused", "BREAK",
                "wrong outcome: code=%r state=%r"
                % (e.code, store.get(rec["request_id"])["state"]))
        return
    _record("p_expired_decide_refused", "BREAK",
            "review of expired request accepted")


def p_double_approve_refused():
    ar = _needs_evidence("p_double_approve_refused")
    if ar is None:
        return
    store, rec = _submit(ar)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    try:
        ar.review(store, rec["request_id"], reviewer="agent:carol",
                  approve=True, now=_NOW + 2)
    except ar.AccessRequestError as e:
        if e.code == "access-request-terminal-refused":
            _record("p_double_approve_refused", "HELD",
                    "second approval on APPROVED refused coded")
            return
    _record("p_double_approve_refused", "BREAK",
            "double approve not refused")


def p_duplicate_review_refused():
    ar = _needs_evidence("p_duplicate_review_refused")
    if ar is None:
        return
    store, rec = _submit(ar, approve_threshold=3)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    try:
        ar.review(store, rec["request_id"], reviewer="agent:bob",
                  approve=True, now=_NOW + 2)
    except ar.AccessRequestError as e:
        if e.code == "access-request-duplicate-review-refused":
            _record("p_duplicate_review_refused", "HELD",
                    "same reviewer voting twice refused coded")
            return
        _record("p_duplicate_review_refused", "BREAK",
                "wrong code: %r" % (e.code,))
        return
    _record("p_duplicate_review_refused", "BREAK",
            "duplicate review accepted")


def p_reviewer_eligibility():
    ar = _needs_evidence("p_reviewer_eligibility")
    if ar is None:
        return
    store, rec = _submit(ar, suggested_reviewers=["agent:bob"])
    try:
        ar.review(store, rec["request_id"], reviewer="agent:mallory",
                  approve=True, now=_NOW + 1)
    except ar.AccessRequestError as e:
        if e.code == "access-request-reviewer-ineligible":
            _record("p_reviewer_eligibility", "HELD",
                    "reviewer outside suggested set refused coded")
            return
        _record("p_reviewer_eligibility", "BREAK",
                "wrong code: %r" % (e.code,))
        return
    _record("p_reviewer_eligibility", "BREAK",
            "ineligible reviewer accepted")


def p_grant_only_when_approved():
    ar = _needs_evidence("p_grant_only_when_approved")
    if ar is None:
        return
    store, rec = _submit(ar)
    try:
        ar.mint_grant(store, rec["request_id"], now=_NOW + 1)
    except ar.AccessRequestError as e:
        if e.code == "access-request-grant-refused":
            _record("p_grant_only_when_approved", "HELD",
                    "mint on PENDING refused coded -- no standing grants")
            return
        _record("p_grant_only_when_approved", "BREAK",
                "wrong code: %r" % (e.code,))
        return
    _record("p_grant_only_when_approved", "BREAK",
            "grant minted for a PENDING request")


def p_grant_ttl_bound():
    ar = _needs_evidence("p_grant_ttl_bound")
    if ar is None:
        return
    from gov import ephemeral_grants as eg
    store, rec = _submit(ar, max_duration_s=600)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 10)
    grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 10)
    tuples = grant["tuples"]
    d_ok = eg.check_grant(principal="agent:alice", action="tool:db_query",
                          tuples=tuples,
                          check_conditions={"now": _NOW + 20})
    d_exp = eg.check_grant(principal="agent:alice", action="tool:db_query",
                           tuples=tuples,
                           check_conditions={"now": _NOW + 10 + 601})
    if d_ok["allowed"] and not d_exp["allowed"] and\
            d_exp["code"] == "delegation-ephemeral-grant-refused":
        _record("p_grant_ttl_bound", "HELD",
                "minted grant allows before expiry, refuses after "
                "(TTL = max_duration from approval)")
    else:
        _record("p_grant_ttl_bound", "BREAK",
                "TTL enforcement wrong: ok=%r expired=%r" % (d_ok, d_exp))


def p_no_scope_widening():
    ar = _needs_evidence("p_no_scope_widening")
    if ar is None:
        return
    from gov import ephemeral_grants as eg
    store, rec = _submit(ar, grants=[{"tool": "tool:db_query"}])
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1)
    d = eg.check_grant(principal="agent:alice", action="tool:db_admin",
                       tuples=grant["tuples"],
                       check_conditions={"now": _NOW + 2})
    if not d["allowed"] and d["code"] == "delegation-ephemeral-grant-refused":
        _record("p_no_scope_widening", "HELD",
                "grant for tool:db_query does not authorize tool:db_admin")
    else:
        _record("p_no_scope_widening", "BREAK",
                "scope widening not refused: %r" % (d,))


def p_single_use_lease():
    ar = _needs_evidence("p_single_use_lease")
    if ar is None:
        return
    from gov import ephemeral_grants as eg
    store, rec = _submit(ar)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    ledger = eg.SpentLeaseRegistry()
    grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1,
                          lease="single-use")
    lease_ref = grant["lease_ref"]
    d1 = eg.check_grant(principal="agent:alice", action="tool:db_query",
                        tuples=grant["tuples"],
                        check_conditions={"now": _NOW + 2},
                        lease_ref=lease_ref, spent_ledger=ledger)
    d2 = eg.check_grant(principal="agent:alice", action="tool:db_query",
                        tuples=grant["tuples"],
                        check_conditions={"now": _NOW + 3},
                        lease_ref=lease_ref, spent_ledger=ledger)
    if d1["allowed"] and not d2["allowed"]:
        _record("p_single_use_lease", "HELD",
                "single-use lease spent on first use, replay refused")
    else:
        _record("p_single_use_lease", "BREAK",
                "single-use semantics wrong: %r %r" % (d1, d2))


def p_join_key_evidence():
    ar = _needs_evidence("p_join_key_evidence")
    if ar is None:
        return
    log = _new_log()
    writer = ar.AccessRequestWriter(log)
    store = ar.AccessRequestStore()
    rec = ar.submit(store, requestor="agent:alice", grants=_GRANTS,
                    reason="nightly report", max_duration_s=3600,
                    now=_NOW, writer=writer)
    ar.review(store, rec["request_id"], reviewer="agent:bob", approve=True,
              now=_NOW + 1, writer=writer)
    grant = ar.mint_grant(store, rec["request_id"], now=_NOW + 1,
                          writer=writer)
    jid = rec["request_id"]
    events = ar.access_request_events(log, jid)
    kinds = [e["event"] for e in events]
    joins = {e["join_key"] for e in events}
    replayed = ar.replay_state(log, jid)
    if kinds == ["submitted", "review", "approved", "grant-issued"] and\
            joins == {jid} and replayed == "APPROVED" and\
            grant["join_key"] == jid:
        _record("p_join_key_evidence", "HELD",
                "decision<->evidence joined by join_key; offline replay "
                "re-derives APPROVED")
    else:
        _record("p_join_key_evidence", "BREAK",
                "join-key evidence wrong: kinds=%r joins=%r replay=%r"
                % (kinds, joins, replayed))


def p_events_chained():
    ar = _needs_evidence("p_events_chained")
    if ar is None:
        return
    from gov.log import read_entries
    log = _new_log()
    writer = ar.AccessRequestWriter(log)
    store = ar.AccessRequestStore()
    rec = ar.submit(store, requestor="agent:alice", grants=_GRANTS,
                    reason="nightly report", max_duration_s=3600,
                    now=_NOW, writer=writer)
    ar.review(store, rec["request_id"], reviewer="agent:bob", approve=True,
              now=_NOW + 1, writer=writer)
    events = [e for e in read_entries(log.path)
              if e.get("record_type") == "access-request-event"]
    ok = True
    prev = "0" * 64
    for e in events:
        if e.get("prev_access_request_digest") != prev:
            ok = False
            break
        prev = e["record_digest"]
    if ok and len(events) >= 3 and writer.verify(log):
        _record("p_events_chained", "HELD",
                "per-writer digest chain continuous across %d events" %
                len(events))
    else:
        _record("p_events_chained", "BREAK",
                "chain broken or unverifiable")


def p_mint_after_ttl_refused():
    ar = _needs_evidence("p_mint_after_ttl_refused")
    if ar is None:
        return
    store, rec = _submit(ar, max_duration_s=600)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    try:
        ar.mint_grant(store, rec["request_id"], now=_NOW + 1 + 601)
    except ar.AccessRequestError as e:
        if e.code == "access-request-grant-refused":
            _record("p_mint_after_ttl_refused", "HELD",
                    "mint after grant TTL elapsed refused coded -- "
                    "no dead-on-arrival grants")
            return
    _record("p_mint_after_ttl_refused", "BREAK",
            "dead-on-arrival mint accepted")


def p_snapshot_restore():
    ar = _needs_evidence("p_snapshot_restore")
    if ar is None:
        return
    store, rec = _submit(ar, approve_threshold=2)
    ar.review(store, rec["request_id"], reviewer="agent:bob",
              approve=True, now=_NOW + 1)
    snap = store.snapshot()
    store2 = ar.AccessRequestStore.restore(snap)
    r2 = store2.get(rec["request_id"])
    if r2 is not None and r2["state"] == "PENDING" and\
            len(r2["reviews"]) == 1:
        _record("p_snapshot_restore", "HELD",
                "store snapshot/restore round-trips pending state "
                "(durability seam)")
    else:
        _record("p_snapshot_restore", "BREAK",
                "snapshot/restore lost state: %r" % (r2,))


def p_taxonomy_pin():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    raws = [e["code"] for e in decision_codes.TAXONOMY.values()]
    uniq = len(set(raws))
    if n == TAXONOMY_PIN and uniq == TAXONOMY_PIN:
        _record("p_taxonomy_pin", "HELD",
                "taxonomy %d/%d unique sorted" % (n, uniq))
    else:
        _record("p_taxonomy_pin", "BREAK",
                "taxonomy pin drift: %d raw / %d unique, want %d"
                % (n, uniq, TAXONOMY_PIN))


def _green_checks():
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-check", "SKIP", "GOV_SKIP_GREEN=1")
        return
    import subprocess
    mods = ["evals.w280_fga_probes", "tests.test_decision_codes"]
    for mod in mods:
        env = dict(os.environ, GOV_SKIP_GREEN="1")
        p = subprocess.run(
            [sys.executable, "-m", mod], capture_output=True, text=True,
            env=env, timeout=600,
            cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        _record("green-check_" + mod,
                "HELD" if p.returncode == 0 else "BREAK",
                "rc=%d" % p.returncode)


def main():
    os.makedirs(os.environ.get("TMPDIR") or "/tmp", exist_ok=True)
    for probe in (p_module_present, p_submit_requires_reason,
                  p_self_review_refused, p_threshold_not_bypassed,
                  p_deny_is_terminal, p_expired_decide_refused,
                  p_double_approve_refused, p_duplicate_review_refused,
                  p_reviewer_eligibility, p_grant_only_when_approved,
                  p_grant_ttl_bound, p_no_scope_widening,
                  p_single_use_lease, p_join_key_evidence,
                  p_events_chained, p_mint_after_ttl_refused,
                  p_snapshot_restore, p_taxonomy_pin):
        try:
            probe()
        except Exception as e:  # noqa: BLE001 - battery must never die
            _record(probe.__name__, "ERROR", "%r" % (e,))
    _green_checks()
    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    print("w281_teleport: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    probe_lines.emit_dicts(_RESULTS, verdict_key="verdict",
                           pid_key="probe_id", note_key="note")
    mism = [r for r in _RESULTS if r["verdict"] == "ERROR"]
    return 1 if (n_break or mism) else 0


if __name__ == "__main__":
    sys.exit(main())
