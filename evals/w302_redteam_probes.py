"""Wave-302 independent red-team battery: wave-301 workflow seams under attack.

The four wave-301 workflow modules (workflow.py, workflow_saga.py,
workflow_routing.py, workflow_idempotency.py) were built standalone and
never composed. This battery attacks the seams BETWEEN them plus each
module's own authority/checkpoint discipline:

  1. Authority re-verification gaps (F380): gov/workflow.py verifies
     the delegation chain but treats the revocation ledger as optional
     (a revoked chain authorizes when the caller omits the ledger),
     and the completed-step replay path skips ALL authority checks --
     including the actor binding -- so a different actor with garbage
     authority can replay another run's completed steps.
  2. Idempotency authorization gaps (F381): gov/workflow_idempotency.py
     re-verifies authority at begin() but complete()/checkpoint() are
     not caller-bound (any authorized caller can complete another
     actor's in-flight operation with an arbitrary result, poisoning
     the replay cache), and evict_completed() takes no authority
     verifier at all.
  3. Journal durability (F382): gov/workflow.py _load() re-appends
     every record, so the journal file doubles on every restart.
  4. Step-key drift (F383): gov/workflow.py's step-level idempotency
     key path replays stale outputs for a different step name/inputs,
     bypassing the seq-slot drift refusal.
  5. Saga escalation (F384, CLOSED 2026-10-03 wave-303 lane 4): an
     escalated saga had no operator recovery path -- escalation was
     terminal despite "until an operator intervenes". The F384 probe
     is re-pinned to the fixed behavior (recovery via
     describe_escalation / resolve_escalation / retry_compensation).
  6. F379 expected-open control: reproduced on pristine base via the
     wave-301 battery's own probe classes; its BREAKs are reported
     separately from the new F380-F384 BREAKs.

Base: wave-303 merge c9138cc53888 (wave-303 merge composition:
lane 4's file as base; F380/F381/F382-F383 probe classes from
lanes 1/2/3 re-pinned to the closed behavior; header restored
2026-10-03 wave-304 lane A -- the merge had dropped it, leaving
the file unimportable).

Pin 1827 at wave-303 merge (+4 decision codes from wave-303
lanes 1-3; F380-F384 CLOSED). Next free F387.
Wave-304 lane A: F385 CLOSED; lane footer open F386 / next free F387.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g302-rt && TMPDIR=/var/tmp/g302-rt \\
    ~/workspace/.gov-venv/bin/python evals/w302_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g302-rtb \\
    ~/workspace/.gov-venv/bin/python evals/w302_redteam_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import re
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)

from gov import delegation as dg
from gov import delegation_revocation as rev
from gov import ed25519 as _ed25519
from gov import workflow as wf
from gov import workflow_idempotency as idem
from gov import workflow_routing as wr
from gov import workflow_saga as saga

TAXONOMY_PIN = 1984 # Wave-301 merge pin 1812; this lane mints no codes.; Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 4: pin 1820 -> 1822 (+2 workflow-saga-*); Wave-303 merge: pin 1822 -> 1826 (+4 codes from lanes 1-3); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

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


def _seed(tag):
    return hashlib.sha256(("w302-redteam-%s" % tag).encode()).digest()


def _pub(seed):
    return _ed25519.publickey(seed).hex()


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


class BaseStateTest(unittest.TestCase):
    def test_footer_state(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        # Wave-316 merge footer: F398/F399/F400 CLOSED; F401/F402/F403 OPEN; next F404.
        ok = (m_open and m_open[-1].strip()
              == "none"
              and m_next and m_next[-1] == "F407")
        self.assertTrue(_expect_held(
            "footer-state", ok,
            "want open F406 / next free F407")
            == "HELD")

    def test_pin(self):
        lits = _literals()
        ok = (len(lits) == TAXONOMY_PIN and len(set(lits)) == TAXONOMY_PIN
              and lits == sorted(lits))
        self.assertTrue(_expect_held(
            "taxonomy-pin",
            ok and TAXONOMY_PIN == 1984,
            "%d literals / %d unique / sorted=%s"
            % (len(lits), len(set(lits)), lits == sorted(lits))) == "HELD")


# ---------------------------------------------------------------------------
# F379 expected-open control (wave-302 lane 1's closure, not this lane's).
# ---------------------------------------------------------------------------

class F379ControlTest(unittest.TestCase):
    def test_F379_closure_holds(self):
        # Wave-302 merge: F379 CLOSED by lane 1 (per-delegator revoker
        # sets). This control verifies the closure holds on the merged
        # tree -- both F379 probes must HELD (they BREAKed on the
        # pre-fix base; see wave-302 merge report for the red-first
        # audit). Reported separately from this lane's new findings.
        import evals.w301_redteam_probes as w301
        before = len(w301._results)
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        cls = w301.RevokeLeaseSeamTest
        suite.addTest(cls(
            "test_F379_multihop_intermediate_revocation_invisible"))
        suite.addTest(cls(
            "test_F379_correct_revoker_structurally_refused"))
        runner = unittest.TextTestRunner(verbosity=0, stream=open(
            os.devnull, "w"))
        runner.run(suite)
        new = w301._results[before:]
        helds = sorted(n for n, s, _ in new if s == "HELD")
        ok = (helds == ["F379-correct-revoker-enforced",
                        "F379-intermediate-revocation-fenced"])
        for n in ("F379-intermediate-revocation-fenced",
                  "F379-correct-revoker-enforced"):
            _record(n, "HELD" if n in helds else "BREAK",
                    "F379 closure control (CLOSED wave-302 lane 1)")
        self.assertTrue(_expect_held(
            "F379-closure-holds", ok,
            "F379 control helds: %s" % (helds,)) == "HELD")


# ---------------------------------------------------------------------------
# Delegation-chain helpers for the workflow authority probes.
# ---------------------------------------------------------------------------

_AT = 1_700_000_000


def _wf_chain(seed, delegator_id, delegatee_id, delegatee_pub):
    cons = {"expires_at": _AT + 3600, "max_depth": 4,
            "allowed_targets": [delegatee_id]}
    return dg.issue(seed, delegator_id, delegatee_id, delegatee_pub,
                    ["tool.invoke"], issued_at=_AT, constraints=cons)


def _wf_auth(chain, actor="agent-b", ledger="default"):
    d = {"actor_id": actor, "action": "tool.invoke", "chain": chain,
         "trust_roots": [_pub(_seed("wf-root"))]}
    if ledger == "default":
        d["revocation_ledger"] = rev.DelegationRevoker(
            _seed("wf-root"), "agent-a")
    elif ledger is not None:
        d["revocation_ledger"] = ledger
    return d


def _wf_actor_pair():
    sa, sb = _seed("wf-root"), _seed("wf-agent")
    return sa, sb, _pub(sa), _pub(sb)


# ---------------------------------------------------------------------------
# Target 1: workflow authority re-verification gaps (F380).
# ---------------------------------------------------------------------------

class WorkflowAuthoritySeamTest(unittest.TestCase):
    """gov/workflow.py: the revocation ledger is optional (a revoked
    chain authorizes when the caller omits it), and the completed-step
    replay path skips ALL authority checks including the actor binding.
    """

    def _revoked(self):
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        ledger = rev.DelegationRevoker(sa, "agent-a")
        ledger.revoke(chain[0]["receipt_id"], _AT + 5)
        return sa, pa, chain, ledger

    def test_F380_revoked_chain_no_ledger_executes(self):
        # F380 (MEDIUM, CLOSED wave-303 lane 1): _verify_authority fails
        # closed when the revocation ledger is absent -- a revoked chain
        # can no longer authorize by omitting the ledger. The step must
        # refuse coded workflow-authority-revoked.
        sa, pa, chain, ledger = self._revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="f380a",
                        authority=_wf_auth(chain), at=_AT)
        auth_noledeger = _wf_auth(chain, ledger=None)
        code = None
        try:
            out, replayed = store.run_step(
                "f380a", 0, "s0", lambda i: {"done": 1},
                authority=auth_noledeger, at=_AT + 10)
            broke = True
        except Exception as e:  # noqa: BLE001
            broke = False
            code = getattr(e, "code", None)
        self.assertTrue(_expect_held(
            "F380-revoked-no-ledger-executes", not broke,
            "step executed under a revoked chain with the ledger omitted")
            == "HELD")
        self.assertEqual(code, "workflow-authority-revoked")

    def test_F380_replay_completed_no_authority_check(self):
        # F380 (MEDIUM, CLOSED wave-303 lane 1): the completed-step
        # replay path in run_step re-verifies authority BEFORE returning
        # recorded outputs -- a replay with a revoked chain (no ledger)
        # now refuses coded workflow-authority-revoked.
        sa, pa, chain, ledger = self._revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="f380b",
                        authority=_wf_auth(chain), at=_AT)
        store.run_step("f380b", 0, "s0", lambda i: {"v": 1},
                       authority=_wf_auth(chain), at=_AT)
        auth_noledeger = _wf_auth(chain, ledger=None)
        code = None
        try:
            res = store.replay(
                "f380b", [{"seq": 0, "name": "s0",
                           "fn": lambda i: {"evil": 1}, "inputs": {}}],
                authority=auth_noledeger, at=_AT + 10)
            broke = res[0][4] == {"v": 1}
        except Exception as e:  # noqa: BLE001
            broke = False
            code = getattr(e, "code", None)
        self.assertTrue(_expect_held(
            "F380-replay-no-authority-check", not broke,
            "replay of completed steps skipped authority verification")
            == "HELD")
        self.assertEqual(code, "workflow-authority-revoked")

    def test_F380_replay_cross_actor_garbage_authority(self):
        # F380 (MEDIUM, CLOSED wave-303 lane 1): the actor binding is
        # re-verified on replay. A DIFFERENT actor presenting garbage
        # authority can no longer replay another run's completed step
        # outputs -- refuses coded workflow-step-unauthorized.
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="f380c",
                        authority=_wf_auth(chain), at=_AT)
        store.run_step("f380c", 0, "s0", lambda i: {"secret": "A"},
                       authority=_wf_auth(chain), at=_AT)
        garbage = {"actor_id": "mallory", "action": "tool.invoke",
                   "chain": [], "trust_roots": []}
        code = None
        try:
            res = store.replay(
                "f380c", [{"seq": 0, "name": "s0",
                           "fn": lambda i: {"evil": 1}, "inputs": {}}],
                authority=garbage, at=_AT + 10)
            broke = res[0][4] == {"secret": "A"}
        except Exception as e:  # noqa: BLE001
            broke = False
            code = getattr(e, "code", None)
        self.assertTrue(_expect_held(
            "F380-replay-cross-actor", not broke,
            "cross-actor replay with garbage authority succeeded")
            == "HELD")
        self.assertEqual(code, "workflow-step-unauthorized")

    def test_F380_control_with_ledger_refuses(self):
        # Control: with the ledger presented, the revoked chain refuses
        # coded workflow-authority-revoked.
        sa, pa, chain, ledger = self._revoked()
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="f380d",
                        authority=_wf_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F380-control-with-ledger-refuses",
            lambda: store.run_step(
                "f380d", 0, "s0", lambda i: {"done": 1},
                authority=_wf_auth(chain, ledger=ledger), at=_AT + 10),
            {"workflow-authority-revoked"}) == "HELD")

    def test_F380_control_fresh_chain_executes(self):
        # Control: the honest path (fresh chain WITH a revocation
        # ledger) works. F380 closure: the ledger is now REQUIRED, so
        # the honest caller presents one.
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="f380e",
                        authority=_wf_auth(chain), at=_AT)
        out, replayed = store.run_step(
            "f380e", 0, "s0", lambda i: {"ok": 1},
            authority=_wf_auth(chain), at=_AT)
        self.assertTrue(_expect_held(
            "F380-control-fresh-chain-executes",
            out == {"ok": 1} and replayed is False,
            "honest path broken") == "HELD")


# ---------------------------------------------------------------------------
# Target 2: idempotency authorization gaps (F381).
# ---------------------------------------------------------------------------

def _idem_verifier(**kw):
    return True


class IdempotencyAuthSeamTest(unittest.TestCase):
    """gov/workflow_idempotency.py: begin() re-verifies authority, and
    (F381 CLOSED 2026-10-03 wave-303 lane 2) complete()/checkpoint() are
    now bound to the beginning caller (coded
    workflow-idempotency-caller-mismatch on mismatch) and
    evict_completed() requires a verified authority verifier."""

    def test_F381_cross_caller_complete_poisons_replay(self):
        # F381 (MEDIUM, CLOSED 2026-10-03 wave-303 lane 2): mallory begins
        # the SAME key (same digest) and gets a RETRY outcome on alice's
        # in-flight record; her complete() is now refused coded
        # workflow-idempotency-caller-mismatch -- the outcome is bound to
        # its beginning caller. The replay cache cannot be poisoned.
        backing = {}
        s1 = idem.IdempotencyStore(backing=backing)
        s2 = idem.IdempotencyStore(backing=backing)
        opd = "ab" * 32
        o1 = s1.begin("ns1", "pay", "k1", opd, "alice",
                      _idem_verifier, at=_AT)
        assert o1.status == "new"
        o2 = s2.begin("ns1", "pay", "k1", opd, "mallory",
                      _idem_verifier, at=_AT)
        assert o2.status == "retry"
        self.assertTrue(_expect_coded(
            "F381-cross-caller-complete-poisons",
            lambda: o2.complete("cd" * 32, "mallory-result-ref", at=_AT),
            {"workflow-idempotency-caller-mismatch"}) == "HELD")
        # Alice's honest completion still lands; nothing of mallory's is
        # replayable.
        o1b = s1.begin("ns1", "pay", "k1", opd, "alice",
                       _idem_verifier, at=_AT)
        o1b.complete("ef" * 32, "alice-result-ref", at=_AT)
        o3 = s1.begin("ns1", "pay", "k1", opd, "alice",
                      _idem_verifier, at=_AT)
        self.assertTrue(_expect_held(
            "F381-no-poisoning-after-refusal",
            o3.status == "replay" and o3.result_ref == "alice-result-ref",
            "replay cache poisoned or honest completion broken")
            == "HELD")

    def test_F381_evict_completed_unauthenticated(self):
        # F381 (MEDIUM, CLOSED 2026-10-03 wave-303 lane 2):
        # evict_completed() now requires an authority verifier -- the
        # old call shape (operator NAME, no verifier) fails closed
        # instead of evicting.
        s = idem.IdempotencyStore()
        opd = "ab" * 32
        o = s.begin("ns1", "pay", "k2", opd, "alice",
                    _idem_verifier, at=_AT)
        o.complete("ab" * 32, "ref", at=_AT)
        try:
            s.evict_completed("ns1", "pay", "k2",
                              operator="mallory", at=_AT)
            refused = False
        except Exception:  # noqa: BLE001
            refused = True
        self.assertTrue(_expect_held(
            "F381-evict-unauthenticated", refused,
            "eviction without an authority verifier succeeded")
            == "HELD")
        # The authorized path still works and stays loud.
        rec = s.evict_completed("ns1", "pay", "k2", operator="ops",
                                authority_verifier=_idem_verifier, at=_AT)
        self.assertTrue(_expect_held(
            "F381-evict-authorized-loud", rec["reason"] == "operator",
            "authorized eviction broke") == "HELD")

    def test_F381_cross_caller_checkpoint(self):
        # F381 (MEDIUM, CLOSED 2026-10-03 wave-303 lane 2): checkpoint()
        # has the same caller binding -- mallory cannot append progress
        # notes to alice's in-flight record.
        backing = {}
        s1 = idem.IdempotencyStore(backing=backing)
        s2 = idem.IdempotencyStore(backing=backing)
        opd = "ab" * 32
        s1.begin("ns1", "pay", "k3", opd, "alice",
                 _idem_verifier, at=_AT)
        o2 = s2.begin("ns1", "pay", "k3", opd, "mallory",
                      _idem_verifier, at=_AT)
        self.assertTrue(_expect_coded(
            "F381-cross-caller-checkpoint",
            lambda: o2.checkpoint("mallory was here", at=_AT),
            {"workflow-idempotency-caller-mismatch"}) == "HELD")

    def test_F381_control_digest_conflict_refuses(self):
        # Control: same key + different digest refuses coded.
        s = idem.IdempotencyStore()
        s.begin("ns1", "pay", "k4", "ab" * 32, "alice",
                _idem_verifier, at=_AT)
        self.assertTrue(_expect_coded(
            "F381-control-digest-conflict",
            lambda: s.begin("ns1", "pay", "k4", "cd" * 32, "alice",
                            _idem_verifier, at=_AT),
            {"permit-idempotency-conflict"}) == "HELD")

    def test_F381_control_lapsed_verifier_refuses_begin(self):
        # Control: authority IS verified at begin(); a refusing
        # verifier fails closed.
        s = idem.IdempotencyStore()
        self.assertTrue(_expect_coded(
            "F381-control-lapsed-verifier",
            lambda: s.begin("ns1", "pay", "k5", "ab" * 32, "alice",
                            lambda **kw: False, at=_AT),
            {"workflow-idempotency-authority-lapsed"}) == "HELD")


# ---------------------------------------------------------------------------
# Target 3: workflow journal durability (F382).
# ---------------------------------------------------------------------------

class WorkflowJournalSeamTest(unittest.TestCase):
    """gov/workflow.py: _load() re-appends every record, so the journal
    file doubles on every restart."""

    def _run_file(self, tag):
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        path = "/var/tmp/g302-rt-journal-%s-%d.jsonl" % (tag, os.getpid())
        if os.path.exists(path):
            os.remove(path)
        w = wf.WorkflowStore(path=path)
        w.start_run("etl", run_id="j1", authority=_wf_auth(chain), at=_AT)
        w.run_step("j1", 0, "s0", lambda i: {"x": 1},
                   authority=_wf_auth(chain), at=_AT)
        return path

    def test_F382_reload_doubles_journal(self):
        # F382 (LOW, CLOSED wave-303 lane 3): loading an existing
        # journal re-appended every record, doubling the file each
        # restart. Now: reload is a fixed point (n2 == n1).
        path = self._run_file("dbl")
        n1 = sum(1 for _ in open(path, encoding="utf-8"))
        wf.WorkflowStore(path=path)
        n2 = sum(1 for _ in open(path, encoding="utf-8"))
        os.remove(path)
        self.assertTrue(_expect_held(
            "F382-reload-doubles-journal", n2 == n1,
            "journal grew %d -> %d on reload" % (n1, n2)) == "HELD")

    def test_F382_control_tampered_middle_line_refuses(self):
        # Control: a corrupted non-final line refuses coded on load.
        path = self._run_file("tamper")
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        lines[0] = lines[0][:-2] + "ff"
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        self.assertTrue(_expect_coded(
            "F382-control-tamper-refuses",
            lambda: wf.WorkflowStore(path=path),
            {"workflow-checkpoint-tampered"}) == "HELD")
        os.remove(path)

    def test_F382_control_crash_tear_tolerated(self):
        # Control: a trailing partial line (crash tear) is tolerated.
        path = self._run_file("tear")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write('{"type": "step", "half-writ')
        try:
            w = wf.WorkflowStore(path=path)
            ok = w.run_status("j1") == "running"
        except Exception:  # noqa: BLE001
            ok = False
        self.assertTrue(_expect_held(
            "F382-control-tear-tolerated", ok,
            "crash tear not tolerated") == "HELD")
        os.remove(path)


# ---------------------------------------------------------------------------
# Target 4: workflow step-key drift (F383).
# ---------------------------------------------------------------------------

class WorkflowStepKeySeamTest(unittest.TestCase):
    """gov/workflow.py: the step-level idempotency-key path replays
    recorded outputs for a DIFFERENT step name/inputs, bypassing the
    seq-slot drift refusal."""

    def test_F383_key_path_skips_drift_checks(self):
        # F383 (LOW, CLOSED wave-303 lane 3): completing (seq 0, name
        # "step-a", inputs X) under key K and then (seq 5, name
        # "step-B-DIFFERENT", inputs Y) under key K used to replay A's
        # outputs. Now: the key path applies drift checks and refuses
        # coded workflow-step-unauthorized.
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="k1", authority=_wf_auth(chain),
                        at=_AT)
        out, replayed = store.run_step(
            "k1", 0, "step-a", lambda i: {"v": "A"}, inputs={"in": 1},
            idempotency_key="K", authority=_wf_auth(chain), at=_AT)
        assert (out, replayed) == ({"v": "A"}, False)
        try:
            out2, replayed2 = store.run_step(
                "k1", 5, "step-B-DIFFERENT", lambda i: {"v": "B"},
                inputs={"in": 999}, idempotency_key="K",
                authority=_wf_auth(chain), at=_AT)
            broke = (out2 == {"v": "A"} and replayed2 is True)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
            broke = code != "workflow-step-unauthorized"
        self.assertTrue(_expect_held(
            "F383-key-path-skips-drift", not broke,
            "different name/inputs replayed stale outputs") == "HELD")

    def test_F383_control_seq_slot_drift_refuses(self):
        # Control: the seq-slot path refuses definition drift coded.
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="k2", authority=_wf_auth(chain),
                        at=_AT)
        store.run_step("k2", 0, "step-a", lambda i: {"v": "A"},
                       inputs={"in": 1}, authority=_wf_auth(chain), at=_AT)
        self.assertTrue(_expect_coded(
            "F383-control-seq-drift-refuses",
            lambda: store.run_step(
                "k2", 0, "step-a", lambda i: {"v": "B"},
                inputs={"in": 999}, authority=_wf_auth(chain), at=_AT),
            {"workflow-step-unauthorized"}) == "HELD")


# ---------------------------------------------------------------------------
# Target 5: saga escalation terminality (F384).
# ---------------------------------------------------------------------------

class SagaEscalationSeamTest(unittest.TestCase):
    """gov/workflow_saga.py: F384 (LOW, CLOSED 2026-10-03 wave-303 lane
    4) -- the operator recovery path (describe_escalation /
    resolve_escalation / retry_compensation) resolves escalations that
    previously refused run/resume terminally."""

    def _escalated(self, tag):
        saga.clear_ops()
        saga.register_op("esc-act-%s" % tag, lambda p: ({"ok": 1}, []))
        def bad_comp(p):
            raise RuntimeError("downstream still down")
        saga.register_op("esc-comp-%s" % tag, bad_comp)
        saga.register_op("esc-fail-%s" % tag, lambda p: 1 / 0)
        mgr = saga.SagaManager(max_compensation_attempts=1)
        d = mgr.define([
            saga.SagaStepDef("s1", "esc-act-%s" % tag, {},
                             "esc-comp-%s" % tag, {}),
            saga.SagaStepDef("s2", "esc-fail-%s" % tag, {},
                             "esc-comp-%s" % tag, {}),
        ])
        inst = mgr.start(d, saga_id="esc-%s" % tag)
        try:
            mgr.run(inst)
        except saga.SagaError:
            pass
        return mgr, inst

    def test_F384_escalation_has_no_recovery_path(self):
        # F384 (LOW, CLOSED 2026-10-03, wave-303 lane 4): re-pinned to
        # the fixed behavior. The operator recovery path now exists:
        # escalate, then recover through the operator API with valid
        # operator authority -- the saga must reach "compensated" and
        # the recovery must be journaled.
        saga.clear_ops()
        tag = "repin"
        saga.register_op("esc-act-%s" % tag, lambda p: ({"ok": 1}, []))
        def bad_comp(p):
            raise RuntimeError("downstream still down")
        saga.register_op("esc-comp-%s" % tag, bad_comp)
        saga.register_op("esc-fail-%s" % tag, lambda p: 1 / 0)
        mgr = saga.SagaManager(max_compensation_attempts=1,
                               operator_authority_ref="op",
                               authority_verifiers={"op": lambda: True})
        d = mgr.define([
            saga.SagaStepDef("s1", "esc-act-%s" % tag, {},
                             "esc-comp-%s" % tag, {}),
            saga.SagaStepDef("s2", "esc-fail-%s" % tag, {},
                             "esc-comp-%s" % tag, {}),
        ])
        inst = mgr.start(d, saga_id="esc-%s" % tag)
        try:
            mgr.run(inst)
        except saga.SagaError:
            pass
        self.assertEqual(inst.status, "escalated")
        recovery_api = [m for m in dir(mgr)
                        if "escalat" in m.lower()
                        or "recover" in m.lower()
                        or "resolve" in m.lower()
                        or "retry" in m.lower()]
        # Downstream fixed; the operator re-drives the compensation.
        saga.register_op("esc-comp-%s" % tag, lambda p: None)
        mgr.retry_compensation(inst)
        types = [e["type"] for e in inst.history]
        self.assertTrue(_expect_held(
            "F384-escalation-recovery",
            bool(recovery_api) and inst.status == "compensated"
            and "escalation_recovery_started" in types
            and "escalation_resolved" in types,
            "api=%r status=%r" % (recovery_api, inst.status)) == "HELD")

    def test_F384_control_failing_compensation_escalates_loud(self):
        # Control: a failing compensation escalates with the coded
        # refusal, never silently skipped.
        mgr, inst = self._escalated("loud")
        self.assertTrue(_expect_held(
            "F384-control-escalates-loud",
            inst.status == "escalated"
            and inst.escalation_code
            == "workflow-saga-compensation-failed",
            "status=%r code=%r" % (inst.status,
                                   inst.escalation_code)) == "HELD")

    def test_F384_control_reverse_order(self):
        # Control: compensations run in exact reverse completion order.
        saga.clear_ops()
        order = []
        for sid in ("r1", "r2", "r3"):
            saga.register_op("ro-act-%s" % sid,
                             lambda p, _s=sid: ({"s": _s}, []))
            saga.register_op("ro-comp-%s" % sid,
                             lambda p, _s=sid: order.append(_s))
        saga.register_op("ro-fail", lambda p: 1 / 0)
        mgr = saga.SagaManager()
        d = mgr.define([
            saga.SagaStepDef("s1", "ro-act-r1", {}, "ro-comp-r1", {}),
            saga.SagaStepDef("s2", "ro-act-r2", {}, "ro-comp-r2", {}),
            saga.SagaStepDef("s3", "ro-act-r3", {}, "ro-comp-r3", {}),
            saga.SagaStepDef("s4", "ro-fail", {}, "ro-comp-r1", {}),
        ])
        inst = mgr.start(d, saga_id="ro1")
        mgr.run(inst)
        self.assertTrue(_expect_held(
            "F384-control-reverse-order", order == ["r3", "r2", "r1"],
            "compensation order %r" % (order,)) == "HELD")


# ---------------------------------------------------------------------------
# Falsified, not filed: cross-module confusion attempts that HELD.
# ---------------------------------------------------------------------------

class CrossModuleConfusionTest(unittest.TestCase):
    """Shared-vocabulary confusion attempts that the modules refuse."""

    def _slip(self, n_legs=2):
        iseed = _seed("wr-issuer")
        legs = []
        for i in range(n_legs):
            hseed = _seed("wr-handler-%d" % i)
            legs.append({
                "handler_id": "handler-%d" % i,
                "handler_pubkey_hex": _pub(hseed),
                "rights": ["read", "write"],
                "input_digest": "ab" * 32,
                "output_digest": "cd" * 32,
            })
        return wr.issue_slip(iseed, "issuer", legs, _AT), iseed

    def test_routing_slip_tamper_refuses(self):
        # Swapping two legs' handler keys breaks the issuer signature.
        slip, iseed = self._slip()
        tampered = dict(slip)
        legs = [dict(l) for l in slip["legs"]]
        legs[0]["handler_pubkey_hex"], legs[1]["handler_pubkey_hex"] = \
            legs[1]["handler_pubkey_hex"], legs[0]["handler_pubkey_hex"]
        tampered["legs"] = legs
        self.assertTrue(_expect_coded(
            "xmod-routing-tamper-refuses",
            lambda: wr.verify_slip(tampered, [_pub(_seed("wr-issuer")),
                                              _pub(_seed("other"))], _AT),
            {"workflow-routing-slip-tampered"}) == "HELD")

    def test_workflow_actor_mismatch_refuses(self):
        # A different actor cannot run steps in another actor's run
        # (the non-replay path enforces the actor binding).
        sa, sb, pa, pb = _wf_actor_pair()
        chain = [_wf_chain(sa, "agent-a", "agent-b", pb)]
        store = wf.WorkflowStore()
        store.start_run("etl", run_id="xm1",
                        authority=_wf_auth(chain), at=_AT)
        other = dict(_wf_auth(chain))
        other["actor_id"] = "mallory"
        self.assertTrue(_expect_coded(
            "xmod-workflow-actor-mismatch",
            lambda: store.run_step(
                "xm1", 0, "s0", lambda i: {"x": 1},
                authority=other, at=_AT),
            {"workflow-step-unauthorized"}) == "HELD")

    def test_idempotency_cross_namespace_isolation(self):
        # A key completed under (ns1, pay) is invisible under (ns2, pay).
        s = idem.IdempotencyStore()
        opd = "ab" * 32
        o = s.begin("ns1", "pay", "kx", opd, "alice",
                    _idem_verifier, at=_AT)
        o.complete("ab" * 32, "ref", at=_AT)
        o2 = s.begin("ns2", "pay", "kx", opd, "alice",
                     _idem_verifier, at=_AT)
        self.assertTrue(_expect_held(
            "xmod-idempotency-namespace-isolation",
            o2.status == "new",
            "cross-namespace key leaked: %s" % (o2.status,)) == "HELD")

    def test_saga_unknown_authority_fails_closed(self):
        # A step naming an unregistered authority_ref fails the step
        # (and compensates) rather than running unchecked.
        saga.clear_ops()
        saga.register_op("xa-act", lambda p: ({"ok": 1}, []))
        saga.register_op("xa-comp", lambda p: None)
        mgr = saga.SagaManager()  # no verifiers registered
        d = mgr.define([saga.SagaStepDef("s1", "xa-act", {},
                                         "xa-comp", {},
                                         authority_ref="missing-ref")])
        inst = mgr.start(d, saga_id="xa1")
        mgr.run(inst)
        st = inst.steps[0]
        self.assertTrue(_expect_held(
            "xmod-saga-unknown-authority-closed",
            st["state"] == "failed"
            and inst.status in ("compensating", "compensated"),
            "state=%r status=%r" % (st["state"], inst.status)) == "HELD")


# ---------------------------------------------------------------------------
# Depth-1 green checks (honor GOV_SKIP_GREEN).
# ---------------------------------------------------------------------------

def _green_check(battery, expect):
    if os.environ.get("GOV_SKIP_GREEN"):
        return ("HELD", "skipped (depth-1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = "/var/tmp/g302-green-%s" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    path = os.path.join(REPO, "evals", battery)
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            env=env, timeout=600)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s" % (e,))
    if expect in (out.stdout + out.stderr):
        summary = (out.stdout.strip().splitlines() or ["no output"])[0]
        return ("HELD", summary)
    return ("BREAK", (out.stdout.strip().splitlines() or ["no output"])[0])


def _green_check_unittest(path, label):
    if os.environ.get("GOV_SKIP_GREEN"):
        return ("HELD", "skipped (depth-1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = "/var/tmp/g302-green-%s" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, os.path.join(REPO, path)],
            capture_output=True, text=True, env=env, timeout=600)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s" % (e,))
    combined = out.stdout + out.stderr
    if out.returncode == 0 and "\nOK" in combined:
        return ("HELD", "%s OK" % (label,))
    tail = (combined.strip().splitlines() or ["no output"])[-1]
    return ("BREAK", "%s: %s" % (label, tail))


class GreenCheckTest(unittest.TestCase):
    def test_green_w301_redteam(self):
        # Wave-303 lane 4 re-pin: w301's F379 probes were re-pinned to
        # the fixed behavior at the wave-302 merge (F379 CLOSED by lane
        # 1), and its footer probe tracks the merged footer -- the
        # battery is fully green on the current tree.
        # Verified: 0 BREAK / 38 HELD / 0 ERROR.
        status, detail = _green_check(
            "w301_redteam_probes.py", "0 BREAK / 38 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w301-redteam", status == "HELD", detail) == "HELD")

    def test_green_w301_workflow(self):
        status, detail = _green_check(
            "w301_workflow_probes.py",
            "w301_workflow: 0 BREAK / 15 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w301-workflow", status == "HELD", detail) == "HELD")

    def test_green_w301_saga(self):
        status, detail = _green_check_unittest(
            "evals/w301_saga_probes.py", "w301_saga")
        self.assertTrue(_expect_held(
            "green-w301-saga", status == "HELD", detail) == "HELD")

    def test_green_w301_routing(self):
        status, detail = _green_check_unittest(
            "evals/w301_routing_probes.py", "w301_routing")
        self.assertTrue(_expect_held(
            "green-w301-routing", status == "HELD", detail) == "HELD")

    def test_green_w301_idempotency(self):
        status, detail = _green_check_unittest(
            "evals/w301_idempotency_probes.py", "w301_idempotency")
        self.assertTrue(_expect_held(
            "green-w301-idempotency", status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, F379ControlTest,
                WorkflowAuthoritySeamTest, IdempotencyAuthSeamTest,
                WorkflowJournalSeamTest, WorkflowStepKeySeamTest,
                SagaEscalationSeamTest, CrossModuleConfusionTest,
                GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    n_break = sum(1 for _, s, _ in _results if s == "BREAK")
    n_held = sum(1 for _, s, _ in _results if s == "HELD")
    n_err = sum(1 for _, s, _ in _results if s == "ERROR")
    print("w302_redteam: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    if not result.wasSuccessful() or n_break or n_err:
        probe_lines.emit((n, s, probe_lines.first_line(d) if d else "")
                         for n, s, d in _results if s != "HELD")
    return result


if __name__ == "__main__":
    main()
