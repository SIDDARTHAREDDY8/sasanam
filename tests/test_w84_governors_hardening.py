"""Wave-84 governors hardening: regression tests for the break-first
battery (2026-09-23).

Pins the post-fix behavior:
- F130: a second bootstrap() on a live store is refused — policy
  evolution goes through propose(), never a re-genesis (the chained
  record can no longer claim a false prior_version GENESIS with a
  "<genesis>" diff marker hiding the real diff).
- Break-glass PAL contract: declare/use/review refuse blank
  (whitespace-only) purpose / action summary / finding.
- Store lifecycle calls are serialized (RLock): N threads proposing
  against one head then applying -> exactly one apply wins, the rest
  are refused by the token parent-link; the chain cannot fork.
- Tier confusion: a dev-minted approval transplanted onto a
  production change is refused on its (change_id, policy_ref)
  binding (tier/mode claims are bound into the change id).
- Authorship replay: a token minted at head H0 is refused once the
  head moves.
- ToolExecutor.is_governed: True iff the full governed core is
  installed — a policy_store owns the engine AND a delegation_context
  is bound (wave-85: half-core construction is a declared bypass,
  never governed).

Hermetic: temp dirs, explicit test key via tests/__init__, Ed25519
human stand-ins, no network. Deterministic except wall-clock ts
(never asserted on) and thread scheduling (the barrier test asserts
only the deterministic outcome: exactly one winner).
"""

import os
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main
for _p in (_TESTS_DIR, _REPO_MAIN):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import policy_change as _pc  # noqa: E402
from gov import delegation_tokens as _dt  # noqa: E402
from gov.approvals import ApprovalQueue  # noqa: E402
from gov.delegation_tokens import DelegationTrust  # noqa: E402
from gov.executor import ToolExecutor  # noqa: E402
from gov.log import ActionLog, read_entries  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402
from gov.signing import Ed25519Signer  # noqa: E402
import secrets  # noqa: E402

_BASE_POLICY = Path(_REPO_MAIN, "policies", "default.yaml").read_text()
_RULE = ("\n  - id: w84-test-rule\n"
         "    effect: deny\n"
         "    match:\n"
         "      tool: delete_file\n")
_T0 = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def _human():
    return Ed25519Signer(secrets.token_bytes(32))


def _trust(*humans):
    ax, ux = _human(), _human()
    return DelegationTrust(
        human_keys={h.key_id: h.public_key for h in humans},
        authority_keys={ax.key_id: ax.public_key},
        user_issuer_keys={ux.key_id: ux.public_key})


def _store(mode="dev", trust=None, log=None, humans=2,
           session_id="sess-w84"):
    humans_ = [_human() for _ in range(humans)]
    trust = trust or _trust(*humans_)
    store = _pc.GovernedPolicyStore(deployment_mode=mode, trust=trust,
                                    log=log, session_id=session_id)
    return store, humans_, trust


def _bootstrap(store, author, purpose="initial", approvers=()):
    return store.bootstrap(_BASE_POLICY, author, "alice",
                          purpose, approver_signers=approvers or (author,),
                          now=_T0)


def _delegation_context(session_id="sess-w84"):
    """A real bound three-token delegation context (synthetic keys).

    Mirrors the wave-74/wave-85 test shape: user + agent + delegation
    tokens, bound at construction. Used to install the second half of
    the governed core in wiring tests.
    """
    human = _human()
    idp = _human()
    authority = _human()
    trust = _dt.DelegationTrust(
        human_keys={human.key_id: human.public_key},
        authority_keys={authority.key_id: authority.public_key},
        user_issuer_keys={idp.key_id: idp.public_key})
    user_tok = _dt.issue_user_token(
        idp, "user-7", ("tool:read_file",), session_id, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(
        authority, "agent-1", "scout", "user-7",
        ("tool:read_file",), session_id, ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        human, "user-7", user_tok, agent_tok,
        ("tool:read_file",), session_id,
        "https://revoke.example.invalid/deleg", ttl_s=3600)
    return _dt.DelegationContext(
        user_token=user_tok, agent_token=agent_tok,
        delegation_token=deleg_tok, parent_chain=[], trust=trust,
        session_id=session_id)


class TestSecondBootstrapRefused(unittest.TestCase):
    """F130: re-genesis is refused — the chained record can never
    claim a false prior_version GENESIS."""

    def test_second_bootstrap_refused(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        with self.assertRaises(_pc.PolicyChangeError) as cm:
            store.bootstrap(_BASE_POLICY + _RULE, h1, "alice", "again",
                           approver_signers=(h1,), now=_T0)
        self.assertIn("propose()", str(cm.exception))

    def test_second_bootstrap_refused_after_apply(self):
        # The interesting case: a live version exists beyond genesis.
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        chg = store.propose(_BASE_POLICY + _RULE, h1, "alice", "v2",
                            now=_T0)
        store.approve(chg.change_id, h1, now=_T0)
        store.apply(chg.change_id, now=_T0)
        with self.assertRaises(_pc.PolicyChangeError):
            store.bootstrap(_BASE_POLICY, h1, "alice", "re-genesis",
                           approver_signers=(h1,), now=_T0)
        # The live version is untouched by the refused re-genesis.
        self.assertEqual(store.current_version(), chg.new_version)

    def test_first_bootstrap_still_works(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        self.assertIsNotNone(store.current_engine())


class TestHollowJustificationRefused(unittest.TestCase):
    """The PAL contract is purpose-DECLARED: whitespace is not a
    justification."""

    def setUp(self):
        self.h1, self.h2 = _human(), _human()
        self.bg = _pc.BreakGlass(trust=_trust(self.h1, self.h2),
                                 log=None, session_id="sess-w84")

    def test_declare_whitespace_purpose_refused(self):
        for bad in ("", "   ", "\t\n"):
            with self.assertRaises(_pc.BreakGlassError):
                self.bg.declare(bad, 600, self.h1)

    def test_use_whitespace_summary_refused(self):
        d = self.bg.declare("real purpose", 600, self.h1)
        self.bg.activate(d.declaration_id)
        for bad in ("", "   "):
            with self.assertRaises(_pc.BreakGlassError):
                self.bg.use(d.declaration_id, bad)
        # A real summary still works.
        self.bg.use(d.declaration_id, "restarted the pool")

    def test_review_whitespace_finding_refused(self):
        d = self.bg.declare("real purpose", 600, self.h1)
        self.bg.activate(d.declaration_id)
        self.bg.use(d.declaration_id, "did it")
        with self.assertRaises(_pc.BreakGlassError):
            self.bg.review(d.declaration_id, self.h2, "  ")
        self.bg.review(d.declaration_id, self.h2, "justified")


class TestStoreThreadSafety(unittest.TestCase):
    """apply()'s verify-then-swap is check-then-act on the authorship
    head. With the wave-84 RLock, N threads proposing against one
    head and then racing apply() produce exactly one winner — the
    chain cannot fork."""

    def test_concurrent_apply_exactly_one_wins(self):
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        n = 8
        barrier = threading.Barrier(n)
        results = [None] * n

        def worker(i):
            try:
                text = (_BASE_POLICY +
                        "\n  - id: w84-race-%d\n"
                        "    effect: deny\n"
                        "    match:\n"
                        "      tool: read_file\n" % i)
                chg = store.propose(text, h1, "alice", "race %d" % i)
                barrier.wait(timeout=30)  # all proposals parent at H0
                store.approve(chg.change_id, h1)
                barrier.wait(timeout=30)
                try:
                    store.apply(chg.change_id)
                except _pc.PolicyChangeError:
                    results[i] = "refused"
                else:
                    results[i] = "applied"
            except Exception as e:  # noqa: BLE001
                results[i] = "ERROR %s: %s" % (type(e).__name__, e)

        threads = [threading.Thread(target=worker, args=(i,))
                   for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertTrue(all(t.is_alive() is False for t in threads),
                        "worker threads hung: %r" % (results,))
        self.assertTrue(all(r in ("applied", "refused") for r in results),
                        "unexpected worker outcome: %r" % (results,))
        self.assertEqual(results.count("applied"), 1,
                         "chain forked or stalled: %r" % (results,))


class TestTierConfusion(unittest.TestCase):
    """The w78 tier-confusion pin, checked independently on the
    policy-change path: tier/deployment_mode claims are bound into
    the change_id, so a dev-minted approval cannot satisfy a
    production change."""

    def test_cross_mode_approval_transplant_refused(self):
        h1, h2 = _human(), _human()
        trust = _trust(h1, h2)
        dstore = _pc.GovernedPolicyStore(
            deployment_mode="dev", trust=trust, log=None,
            session_id="sess-w84-xmode")
        pstore = _pc.GovernedPolicyStore(
            deployment_mode="production", trust=trust, log=None,
            session_id="sess-w84-xmode")
        dstore.bootstrap(_BASE_POLICY, h1, "alice", "init",
                         approver_signers=(h1,), now=_T0)
        pstore.bootstrap(_BASE_POLICY, h1, "alice", "init",
                         approver_signers=(h1, h2), now=_T0)
        dchg = dstore.propose(_BASE_POLICY + _RULE, h1, "alice", "x",
                              now=_T0)
        pchg = pstore.propose(_BASE_POLICY + _RULE, h1, "alice", "x",
                              now=_T0)
        self.assertNotEqual(dchg.change_id, pchg.change_id)
        ap = _pc.sign_approval(h2, change_id=dchg.change_id,
                               policy_ref=_pc.policy_digest(dchg.text),
                               now=_T0)
        pstore.approve(pchg.change_id, h1, now=_T0)
        pchg.approvals.append(ap)
        with self.assertRaises(_pc.TierError) as cm:
            pstore.apply(pchg.change_id)
        self.assertIn("does not bind", str(cm.exception))


class TestAuthorshipReplay(unittest.TestCase):
    def test_stale_parent_token_refused(self):
        store, (h1,), trust = _store(humans=1)
        _bootstrap(store, h1)
        h0 = store.authorship_head()
        tok = _pc.issue_authorship_token(
            h1, policy_ref="a" * 64, prior_ref="b" * 64,
            parent_token_hash=h0, author="alice", diff_digest="c" * 64,
            tier="single-human", deployment_mode="dev",
            session_id="sess-w84", purpose="x", now=_T0)
        chg = store.propose(_BASE_POLICY + _RULE, h1, "alice", "move",
                            now=_T0)
        store.approve(chg.change_id, h1, now=_T0)
        store.apply(chg.change_id, now=_T0)
        with self.assertRaises(_pc.AuthorshipError):
            _pc.verify_authorship_token(
                tok, trust, expected_parent=store.authorship_head())


class TestIsGoverned(unittest.TestCase):
    def test_is_governed_reflects_wiring(self):
        run_dir = Path(tempfile.mkdtemp(prefix="govred-w84gov-"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        engine = PolicyEngine.from_text(_BASE_POLICY,
                                        source_label="<w84>")
        legacy = ToolExecutor(run_dir, engine, log, approvals,
                              # Wave-85: the is_governed wiring test
                              # deliberately builds the legacy shape; the
                              # bypass is declared, not silent.
                              ungoverned_ack=(
                                  "is_governed test: legacy wiring built "
                                  "deliberately"))
        self.assertFalse(legacy.is_governed)
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        # Wave-85: the governed core is policy_store +
        # delegation_context. The fully governed wiring installs both,
        # so no bypass is declared and none is chained (fresh run_dir
        # so the legacy declaration above cannot confuse the check).
        gov_dir = Path(tempfile.mkdtemp(prefix="govred-w84gov-"))
        gov_log = ActionLog(gov_dir / "actions.jsonl")
        gov_approvals = ApprovalQueue(gov_dir, gov_log)
        governed = ToolExecutor(gov_dir, store.current_engine(), gov_log,
                                gov_approvals, policy_store=store,
                                delegation_context=_delegation_context(),
                                # Wave-100: the governed core is installed,
                                # so the capability posture is declared
                                # explicitly (out of scope for this wiring
                                # test); declared, not silent.
                                capability_ungoverned_ack=(
                                    "is_governed test: fully governed wiring "
                                    "built deliberately; the capability gate "
                                    "is not the subject under test"))
        self.assertTrue(governed.is_governed)
        kinds = [e.get("event")
                 for e in read_entries(gov_dir / "actions.jsonl")]
        self.assertNotIn("ungoverned_bypass", kinds)

    def test_is_governed_false_for_half_core(self):
        # Wave-85 pin: a store-owned engine WITHOUT a delegation
        # context is a declared bypass, not governed — is_governed
        # must not accept half the core.
        run_dir = Path(tempfile.mkdtemp(prefix="govred-w84gov-"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        store, (h1,), _ = _store(humans=1)
        _bootstrap(store, h1)
        half = ToolExecutor(run_dir, store.current_engine(), log,
                            approvals, policy_store=store,
                            ungoverned_ack=(
                                "is_governed test: store-owned engine but "
                                "delegation identity not installed"))
        self.assertFalse(half.is_governed)
        kinds = [e.get("event")
                 for e in read_entries(run_dir / "actions.jsonl")]
        self.assertIn("ungoverned_bypass", kinds)


if __name__ == "__main__":
    unittest.main()
