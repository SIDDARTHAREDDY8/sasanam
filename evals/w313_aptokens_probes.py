#!/usr/bin/env python3
"""Wave-313 Lane B battery: capability-bound, argument-bound approval
tokens (gov/approval_tokens.py, Row 7 build step 3).

Break-first probes at the public seams (issue_token / verify_token /
TokenConsumeStore, plus the decide()->sweep wiring). Verdicts:
  HELD = behavior matches the pin (every attack refused coded);
  BREAK = behavior changed vs the pin, or an unexpected miss;
  ERROR = probe/harness problem.

Probe map:
  issue-verify-roundtrip: mint + verify happy path (exact binding).
  refuse-tampered: edited MAC / edited body -> approval-token-tampered.
  refuse-capability-substitution: token for send_email presented for
      delete_file -> approval-token-capability-mismatch.
  refuse-argument-substitution: benign step-1 token presented for the
      harmful step-3 variant -> approval-token-argument-mismatch.
  refuse-argument-widening: token minted for a prefix of the arguments
      does not cover the widened call -> approval-token-argument-mismatch.
  refuse-expired: past expires_at -> approval-token-expired.
  refuse-replay: nonce consumed, presented again ->
      approval-token-replayed.
  refuse-replay-across-runs: a second store hydrated from the first
      store's snapshot (the durability seam a shared store would use)
      refuses the replay -> approval-token-replayed. NOTE: the
      in-memory store is process-local by design; cross-run replay
      without a shared store rides the record MAC's run_id binding
      (F38), documented in the lane report.
  refuse-replay-after-expiry: a token that is BOTH expired and replayed
      refuses approval-token-expired (check order: expiry before
      replay) -- pinned, not accidental.
  schema-binding: declared-schema accept + undeclared-value / widening
      / narrowing refusals (type-strict).
  decomposed-reuse: the compositional attack the decomp corpus
      measures -- step 1 approved benign, step 3 reuses the token for
      a harmful variant of the same capability -> refused coded.
  sweep-integration: queue -> decide mints the token; execute_approved
      verifies it as an additional check and executes; a swapped token
      (re-MACed by a key-holding record writer, the F29 residual class)
      is refused with approval-token-argument-mismatch and never
      executes.
  backward-compat-no-token: a record carrying no token sweeps exactly
      as before (the check is additional, not a replacement).
  pin-taxonomy / footer-state: standard pins (1900; open none / next F398).

Deterministic across 2 runs; $0 spend; synthetic/local. Stdlib only
apart from gov/approval_tokens.py (real product code, no stubs).

Run:
  mkdir -p /var/tmp/g313-aptok
  TMPDIR=/var/tmp/g313-aptok ~/workspace/.gov-venv/bin/python evals/w313_aptokens_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g313-aptokb ~/workspace/.gov-venv/bin/python evals/w313_aptokens_probes.py
Single-probe mode:
  ~/workspace/.gov-venv/bin/python evals/w313_aptokens_probes.py refuse-replay
"""

import copy
import os
import re
import sys
import traceback

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO, os.path.join(REPO, "tests"), os.path.join(REPO, "evals")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import green_check  # noqa: E402  (shared fail-closed green checks)
import probe_lines  # noqa: E402  (canonical probe-line emission)

from gov import approval_tokens as AT  # noqa: E402

TAXONOMY_PIN = 2140  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).; Wave-343 merge: pin 2131 -> 2134 (+3 ownership-*); Wave-347 lane 6: pin 2134 -> 2135 (+1 policy-delta-mode-weakened); Watcher v1 merge: pin 2135 -> 2140 (+5 vendor-watch-*)


_NOW = 1798765432
_BENIGN = {"to": "teammate@synthetic.local", "body": "weekly report"}
_HARMFUL = {"to": "external-drop@synthetic.local", "body": "weekly report"}

_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a dead
    battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _key():
    # The suite path (tests/__init__.py) provisions a key; standalone
    # battery runs do not import the tests package, so provision one
    # here when absent. Test-only.
    if "GOV_LOG_KEY" not in os.environ:
        try:
            from tests.keyfixture import provision_test_key
        except ImportError:
            from keyfixture import provision_test_key
        provision_test_key()


def _issue_benign(**kw):
    base = {"capability": "send_email",
            "argument_binding": {"mode": "exact", "args": dict(_BENIGN)},
            "issuer": "human-operator", "ttl_seconds": 3600,
            "issued_at": _NOW}
    base.update(kw)
    return AT.issue_token(**base)


def _code_of(fn):
    try:
        fn()
    except AT.ApprovalTokenError as e:
        return e.code
    return None


def _expect(pid, fn, code, note):
    got = _code_of(fn)
    if got == code:
        _record(pid, "HELD", "%s: refused coded %s" % (note, code))
    else:
        _record(pid, "BREAK",
                "%s: expected %s, got %r" % (note, code, got))


# ---------------------------------------------------------------------------
# Probes
# ---------------------------------------------------------------------------

def issue_verify_roundtrip():
    _key()
    tok = _issue_benign()
    body = AT.verify_token(tok, capability="send_email",
                           args=dict(_BENIGN), now=_NOW)
    assert body["capability"] == "send_email", body
    assert body["issuer"] == "human-operator", body
    assert tok["expires_at"] == _NOW + 3600, tok
    _record("issue-verify-roundtrip", "HELD",
            "mint + verify round-trips; expiry bound to issued_at + ttl")


def refuse_tampered():
    _key()
    tok = _issue_benign()
    bad_mac = copy.deepcopy(tok)
    bad_mac["mac"] = "00" + bad_mac["mac"][2:]
    _expect("refuse-tampered",
            lambda: AT.verify_token(bad_mac, capability="send_email",
                                    args=dict(_BENIGN), now=_NOW),
            "approval-token-tampered", "edited MAC")
    bad_body = copy.deepcopy(tok)
    bad_body["capability"] = "delete_file"
    code = _code_of(lambda: AT.verify_token(
        bad_body, capability="delete_file",
        args=dict(_BENIGN), now=_NOW))
    if code == "approval-token-tampered":
        _record("refuse-tampered-body", "HELD",
                "edited body with stale MAC: refused coded "
                "approval-token-tampered")
    else:
        _record("refuse-tampered-body", "BREAK",
                "edited body: expected approval-token-tampered, got %r"
                % (code,))


def refuse_capability_substitution():
    _key()
    tok = _issue_benign()
    _expect("refuse-capability-substitution",
            lambda: AT.verify_token(tok, capability="delete_file",
                                    args=dict(_BENIGN), now=_NOW),
            "approval-token-capability-mismatch",
            "send_email token presented for delete_file")


def refuse_argument_substitution():
    _key()
    tok = _issue_benign()
    _expect("refuse-argument-substitution",
            lambda: AT.verify_token(tok, capability="send_email",
                                    args=dict(_HARMFUL), now=_NOW),
            "approval-token-argument-mismatch",
            "benign step-1 token presented for harmful step-3 variant")


def refuse_argument_widening():
    _key()
    # Token minted for a PREFIX of the arguments...
    tok = _issue_benign(argument_binding={
        "mode": "exact", "args": {"to": "teammate@synthetic.local"}})
    # ...does not cover the widened call.
    _expect("refuse-argument-widening",
            lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "teammate@synthetic.local",
                      "bcc": "external-drop@synthetic.local"},
                now=_NOW),
            "approval-token-argument-mismatch",
            "prefix-minted token vs widened args")


def refuse_expired():
    _key()
    tok = _issue_benign()
    _expect("refuse-expired",
            lambda: AT.verify_token(tok, capability="send_email",
                                    args=dict(_BENIGN), now=_NOW + 3600),
            "approval-token-expired", "one second past expires_at")
    # Boundary: still valid one second before expiry.
    body = AT.verify_token(tok, capability="send_email",
                           args=dict(_BENIGN), now=_NOW + 3599)
    assert body["capability"] == "send_email"
    _record("expiry-boundary", "HELD",
            "valid at expires_at - 1, refused at expires_at")


def refuse_replay():
    _key()
    tok = _issue_benign()
    store = AT.TokenConsumeStore()
    AT.verify_token(tok, capability="send_email", args=dict(_BENIGN),
                    now=_NOW, consume_store=store)
    store.consume(tok["nonce"], now=_NOW)
    _expect("refuse-replay",
            lambda: AT.verify_token(
                tok, capability="send_email", args=dict(_BENIGN),
                now=_NOW, consume_store=store),
            "approval-token-replayed", "nonce already consumed")


def refuse_replay_across_runs():
    _key()
    tok = _issue_benign()
    # Run A consumes the nonce.
    store_a = AT.TokenConsumeStore()
    AT.verify_token(tok, capability="send_email", args=dict(_BENIGN),
                    now=_NOW, consume_store=store_a)
    store_a.consume(tok["nonce"], now=_NOW)
    # Run B hydrates a fresh store from run A's persisted snapshot --
    # the durability seam a shared store would use. The replay key is
    # the nonce, not object identity.
    store_b = AT.TokenConsumeStore.restore(store_a.snapshot())
    _expect("refuse-replay-across-runs",
            lambda: AT.verify_token(
                tok, capability="send_email", args=dict(_BENIGN),
                now=_NOW, consume_store=store_b),
            "approval-token-replayed",
            "snapshot-hydrated store refuses the cross-run replay")


def refuse_replay_after_expiry():
    _key()
    tok = _issue_benign()
    store = AT.TokenConsumeStore()
    store.consume(tok["nonce"], now=_NOW)
    # Both expired AND replayed: the check order (expiry before
    # replay) pins the refusal to approval-token-expired.
    _expect("refuse-replay-after-expiry",
            lambda: AT.verify_token(
                tok, capability="send_email", args=dict(_BENIGN),
                now=_NOW + 7200, consume_store=store),
            "approval-token-expired",
            "expired+replayed pins to approval-token-expired (order)")


def schema_binding():
    _key()
    tok = AT.issue_token(
        "send_email",
        {"mode": "schema", "schema": {
            "to": {"enum": ["teammate@synthetic.local",
                            "manager@synthetic.local"]}}},
        issuer="human-operator", ttl_seconds=3600, issued_at=_NOW)
    body = AT.verify_token(tok, capability="send_email",
                           args={"to": "manager@synthetic.local"},
                           now=_NOW)
    assert body["argument_binding"]["mode"] == "schema"
    _expect("schema-binding-undeclared-value",
            lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "external-drop@synthetic.local"}, now=_NOW),
            "approval-token-argument-mismatch", "undeclared enum value")
    _expect("schema-binding-widening",
            lambda: AT.verify_token(
                tok, capability="send_email",
                args={"to": "teammate@synthetic.local",
                      "bcc": "external-drop@synthetic.local"}, now=_NOW),
            "approval-token-argument-mismatch",
            "extra key past the declared surface")
    _record("schema-binding", "HELD",
            "declared value verifies; undeclared value and widening "
            "refuse coded")


def decomposed_reuse():
    _key()
    # Step 1: approved benign.
    step1 = _issue_benign()
    AT.verify_token(step1, capability="send_email",
                    args=dict(_BENIGN), now=_NOW)
    # Step 3: the same capability, recipient swapped to the exfil
    # target -- the compositional shape the decomp corpus measures.
    code = _code_of(lambda: AT.verify_token(
        step1, capability="send_email", args=dict(_HARMFUL), now=_NOW))
    if code == "approval-token-argument-mismatch":
        _record("decomposed-reuse", "HELD",
                "step-1 benign token does not authorize the step-3 "
                "harmful variant: refused coded "
                "approval-token-argument-mismatch")
    else:
        _record("decomposed-reuse", "BREAK",
                "step-3 reuse: expected "
                "approval-token-argument-mismatch, got %r" % (code,))


def _make_run():
    from harness import make_run
    return make_run()


def sweep_integration():
    _key()
    run = _make_run()
    ident = run["identities"]["support"]
    res = run["executor"].call(
        ident, "send_email", to="teammate@synthetic.local",
        subject="hello", body="hello")
    assert res["status"] == "queued", res
    aid = res["approval_id"]
    run["approvals"].decide(aid, True, reason="looks fine",
                            decided_by="human-operator")
    rec = next(r for r in run["approvals"].all() if r["id"] == aid)
    assert rec.get("approval_token") is not None, "decide() minted no token"
    done = run["executor"].execute_approved()
    if len(done) == 1:
        _record("sweep-integration", "HELD",
                "queue -> decide mints token; sweep verifies it as an "
                "additional check and executes")
    else:
        _record("sweep-integration", "BREAK",
                "expected 1 execution, got %r" % (done,))


def sweep_refuses_swapped_token():
    _key()
    run = _make_run()
    ident = run["identities"]["support"]
    res = run["executor"].call(
        ident, "send_email", to="teammate@synthetic.local",
        subject="hello", body="hello")
    aid = res["approval_id"]
    run["approvals"].decide(aid, True, reason="looks fine",
                            decided_by="human-operator")
    # A key-holding record writer (the F29 residual class) swaps in a
    # token minted for different args and re-MACs the record: the
    # record MAC verifies, but the token's own binding refuses.
    from gov.approvals import approval_record_digest
    foreign = AT.issue_token(
        "send_email",
        {"mode": "exact",
         "args": {"to": "other@synthetic.local", "subject": "hello",
                  "body": "hello"}},
        issuer="human-operator", ttl_seconds=3600)
    run["approvals"]._rewrite(lambda records: [
        dict(r, approval_token=foreign,
             args_digest=approval_record_digest(
                 dict(r, approval_token=foreign)))
        if r["id"] == aid else r for r in records])
    done = run["executor"].execute_approved()
    from gov.log import read_entries
    log_path = (getattr(run["log"], "path", None)
                or os.path.join(run["run_dir"], "actions.jsonl"))
    reasons = [e.get("reason", "") for e in read_entries(log_path)
               if e.get("event") == "approval_execution_refused"
               and e.get("approval_id") == aid]
    if done == [] and any("approval-token-argument-mismatch" in r
                          for r in reasons):
        _record("sweep-refuses-swapped-token", "HELD",
                "swapped token refused coded "
                "approval-token-argument-mismatch; nothing executed")
    else:
        _record("sweep-refuses-swapped-token", "BREAK",
                "done=%r reasons=%r" % (done, reasons))


def backward_compat_no_token():
    _key()
    run = _make_run()
    ident = run["identities"]["support"]
    res = run["executor"].call(
        ident, "send_email", to="teammate@synthetic.local",
        subject="hello", body="hello")
    aid = res["approval_id"]
    run["approvals"].decide(aid, True, reason="looks fine",
                            decided_by="human-operator")
    # Strip the token (re-MAC honestly): the sweep must behave exactly
    # as before the token existed.
    from gov.approvals import approval_record_digest
    run["approvals"]._rewrite(lambda records: [
        dict(r, approval_token=None,
             args_digest=approval_record_digest(
                 dict(r, approval_token=None)))
        if r["id"] == aid else r for r in records])
    done = run["executor"].execute_approved()
    if len(done) == 1:
        _record("backward-compat-no-token", "HELD",
                "record without a token sweeps unchanged (check is "
                "additional, not a replacement)")
    else:
        _record("backward-compat-no-token", "BREAK",
                "expected 1 execution, got %r" % (done,))


def pin_taxonomy():
    from gov import decision_codes
    n = len(decision_codes.TAXONOMY)
    if n != TAXONOMY_PIN:
        _record("pin-taxonomy", "BREAK",
                "taxonomy literals %d != pin %d" % (n, TAXONOMY_PIN))
    else:
        _record("pin-taxonomy", "HELD",
                "taxonomy pin %d holds" % TAXONOMY_PIN)


def footer_state():
    with open(os.path.join(REPO, "evals", "FINDINGS.md"),
              encoding="utf-8") as fh:
        text = fh.read()
    # Wave-359 merge: F482-F488 CLOSED; F489-F495 OPEN; next F496.
    # This lane files no findings. Footer lines repeat through history;
    # the LAST one is current.
    m_open = re.findall(r"Open findings: ([^*]*)\.", text)
    ok = ("Next free finding: **F570**" in text  # Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
          and "**Open findings: F547, F548, F549, F550, F551, F552, F553, F554, F555, F556, F557, F558, F559, F560, F561, F562, F563, F564, F565, F566, F567, F568, F569.**" in text)  # Wave-360 merge: F489-F495 CLOSED; F496-F502 OPEN; next F503.; Wave-364 merge: F513-F520 CLOSED; F521-F525 filed OPEN (next F526)  # Wave-365 merge: F521-F525 CLOSED; F526-F530 filed OPEN (next F531)  # Wave-366 merge: F526-F530 CLOSED (lanes 1-3); F532 CLOSED at merge (honest F527 generalization, F514 precedent); F531, F533-F536 OPEN (next F537)  # Wave-368 merge: F537-F546 CLOSED (lanes 1-4); F547-F569 filed OPEN (next F570)
    if ok:
        _record("footer-state", "HELD", "footer: open F436 / next F437")
    else:
        _record("footer-state", "BREAK",
                "footer mismatch vs open F503, F504, F505 / next F506")


PROBES = [issue_verify_roundtrip, refuse_tampered,
          refuse_capability_substitution, refuse_argument_substitution,
          refuse_argument_widening, refuse_expired, refuse_replay,
          refuse_replay_across_runs, refuse_replay_after_expiry,
          schema_binding, decomposed_reuse, sweep_integration,
          sweep_refuses_swapped_token, backward_compat_no_token,
          pin_taxonomy, footer_state]


def _green_checks():
    # Depth-1 green checks on the adjacent seam battery (fail-closed via
    # the shared helper; GOV_SKIP_GREEN=1 records a skip, never spawns).
    green_check.check_battery(_record, "green-decomp-corpus",
                              "evals/decomp_corpus_probes.py", repo=REPO)


def run_once(only=None):
    del _results[:]
    for p in PROBES:
        if only and only not in p.__name__:
            continue
        _safe(p.__name__, p)
    if only is None:
        _green_checks()
    return list(_results)


def main(argv):
    only = argv[1] if len(argv) > 1 else None
    first = run_once(only)
    second = run_once(only)
    det = ([v for _, v, _ in first] == [v for _, v, _ in second])
    n_held = sum(1 for _, v, _ in first if v == "HELD")
    n_break = sum(1 for _, v, _ in first if v == "BREAK")
    n_err = sum(1 for _, v, _ in first if v == "ERROR")
    probe_lines.emit(first)
    ok, diags = probe_lines.check_coherence(first, n_break, n_held, n_err)
    if not ok:
        for d in diags:
            print("coherence-WARNING: %s" % d)
    print("----")
    print("w313_aptokens battery: %d BREAK / %d HELD / %d ERROR "
          "(deterministic across 2 runs: %s)"
          % (n_break, n_held, n_err, det))
    if not det:
        print("NON-DETERMINISTIC across runs -- do not trust")
        return 2
    if n_err:
        print("ERRORs present -- battery failed closed")
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
