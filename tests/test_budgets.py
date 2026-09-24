"""S2 (K-018): hard spend/token/action budget tests (gov/executor.py).

Verifies the S2 guard:

* ``max_actions_per_run``: ceiling uses ``>`` on the attempt count —
  the call that reaches the ceiling completes, the NEXT is denied.
* Token/spend ceilings use ``>=`` on the accrued totals.
* Usage accrues on the RESULT path only (``result["_usage"]`` minted by
  the governed side — never call kwargs, so an agent cannot inflate
  (or deflate) its own usage). F162 wired the accrual (was S2-GAP-1):
  ``_simulate`` mints deterministic usage per executed tool,
  ``_ingest_result`` accrues it, and every executed entry carries
  ``usage`` + ``budget_meter`` on the chained log.
* Denials audit ``policy_id="budget-exceeded"`` / flag
  ``"budget_exceeded"``.
* F162: absent ``budgets:`` section = DEFAULT action ceiling enforced
  (absent is default-enforced, never silently unlimited); explicit
  values always win. Token/spend ceilings stay deployment-configured.
  Malformed sections fail the policy load closed.

Deterministic, stdlib only (unittest), no network, no real systems.
"""

import shutil
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gov.policy import PolicyEngine  # noqa: E402
from tests.harness import make_run  # noqa: E402


def _policy_text(budgets=None, allow_api=True):
    budgets_yaml = ""
    if budgets is not None:
        budgets_yaml = "budgets:\n"
        for k, v in budgets.items():
            budgets_yaml += "  %s: %s\n" % (k, v)
    rules = ""
    if allow_api:
        rules = """\
policies:
  - id: test-allow-api
    effect: allow
    match:
      tool: [api_call]
    reason: Test policy allows api_call.
"""
    return """\
version: 2
roles:
  worker: [api_call, read_file]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
# F162: tempo is raised out of the way in these budget tests so the
# budget under test is what trips (the tight loops would otherwise
# hit the default tempo tripwire first — the designed layering).
tempo:
  window_secs: 60
  max_read: 1000000
  max_write: 1000000
  max_egress: 1000000
%s%s""" % (budgets_yaml, rules)


def _tmpdir(prefix):
    base = Path("/tmp/gov-run")
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


class TestBudgets(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir("govs2-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run(self, budgets=None, allow_api=True):
        p = self.tmp / ("policy_%d.yaml" % id(self))
        p.write_text(_policy_text(budgets, allow_api), encoding="utf-8")
        run = make_run(policy_path=str(p))
        ident = run["mint_identity"]("w1", "worker", "acme")
        return run, ident

    def _api(self, executor, ident, i=0):
        # Vary the endpoint so the identical-call loop guard stays out.
        return executor.call(ident, "api_call",
                             endpoint="https://synthetic.local/x%d" % i)

    # -- action budget ---------------------------------------------------

    def test_actions_ceiling_crossing_call_completes_next_denied(self):
        """max_actions_per_run=2: calls 1 and 2 complete; call 3 is
        denied (``>`` on the attempt count)."""
        run, ident = self._run({"max_actions_per_run": 2})
        ex = run["executor"]
        r1 = self._api(ex, ident, 1)
        r2 = self._api(ex, ident, 2)
        r3 = self._api(ex, ident, 3)
        self.assertEqual(r1["status"], "executed", r1)
        self.assertEqual(r2["status"], "executed", r2)
        self.assertEqual(r3["status"], "denied", r3)
        self.assertEqual(r3["policy_id"], "budget-exceeded", r3)
        self.assertIn("action budget", r3["reason"])

    def test_budget_denial_audits_budget_exceeded(self):
        """A budget denial is audit-visible with the budget_exceeded
        flag and budget-exceeded policy id."""
        run, ident = self._run({"max_actions_per_run": 1})
        ex = run["executor"]
        self._api(ex, ident, 1)
        denied = self._api(ex, ident, 2)
        self.assertEqual(denied["status"], "denied")
        entries = [e for e in run["read_log"]()
                   if e.get("policy_id") == "budget-exceeded"]
        self.assertTrue(entries, "expected a budget-exceeded audit entry")
        last = entries[-1]
        self.assertEqual(last["decision"], "denied")
        self.assertEqual(last["flag"], "budget_exceeded")
        self.assertIn("budget", last["reason"].lower())

    def test_actions_budget_counts_attempts_not_executions(self):
        """The action counter increments for every call() that reaches
        the guard — including calls the policy later denies. Here the
        policy denies everything, yet the 3rd attempt is refused by the
        BUDGET guard (not the policy)."""
        run, ident = self._run({"max_actions_per_run": 2},
                               allow_api=False)
        ex = run["executor"]
        r1 = self._api(ex, ident, 1)
        r2 = self._api(ex, ident, 2)
        r3 = self._api(ex, ident, 3)
        self.assertEqual(r1["status"], "denied")
        self.assertNotEqual(r1.get("policy_id"), "budget-exceeded")
        self.assertEqual(r2["status"], "denied")
        self.assertNotEqual(r2.get("policy_id"), "budget-exceeded")
        self.assertEqual(r3["status"], "denied")
        self.assertEqual(r3["policy_id"], "budget-exceeded", r3)

    def test_zero_action_budget_denies_first_call(self):
        """max_actions_per_run=0 is a valid config meaning 'no calls':
        the first attempt already exceeds it."""
        run, ident = self._run({"max_actions_per_run": 0})
        r = self._api(run["executor"], ident, 1)
        self.assertEqual(r["status"], "denied", r)
        self.assertEqual(r["policy_id"], "budget-exceeded", r)

    # -- token / spend ceilings (>= semantics) ----------------------------

    def test_token_ceiling_ge_convention(self):
        """Token ceiling trips when accrued >= max: the call that
        crossed the ceiling completed, the NEXT is denied.

        White-box pin of the guard's >= convention (totals are seeded
        to what result-path accrual will produce; see S2-GAP-1)."""
        run, ident = self._run({"max_tokens_per_run": 10})
        ex = run["executor"]
        ex._tokens_used = 9
        r = self._api(ex, ident, 1)
        self.assertEqual(r["status"], "executed", r)
        ex._tokens_used = 10
        r = self._api(ex, ident, 2)
        self.assertEqual(r["status"], "denied", r)
        self.assertEqual(r["policy_id"], "budget-exceeded", r)
        self.assertIn("token budget", r["reason"])

    def test_spend_ceiling_ge_convention(self):
        """Spend ceiling trips when accrued >= max (same crossing
        semantics as tokens). White-box pin; see S2-GAP-1."""
        run, ident = self._run({"max_spend_per_run": 0.001})
        ex = run["executor"]
        ex._spend_used = 0.0009
        r = self._api(ex, ident, 1)
        self.assertEqual(r["status"], "executed", r)
        ex._spend_used = 0.001
        r = self._api(ex, ident, 2)
        self.assertEqual(r["status"], "denied", r)
        self.assertEqual(r["policy_id"], "budget-exceeded", r)
        self.assertIn("spend budget", r["reason"])

    # -- the accrual gap (CLOSED by F162) ---------------------------------

    def test_token_accrual_from_result_path(self):
        """F162 (was S2-GAP-1): usage accrues on the RESULT path —
        after executed calls the token total is > 0 and a tiny
        max_tokens_per_run ceiling trips."""
        run, ident = self._run({"max_tokens_per_run": 5})
        ex = run["executor"]
        statuses = [self._api(ex, ident, i)["status"] for i in range(10)]
        self.assertGreater(ex._tokens_used, 0,
                           "no token usage accrued from executed calls")
        self.assertIn("denied", statuses,
                      "max_tokens_per_run=5 never tripped over 10 calls")

    def test_spend_accrual_from_result_path(self):
        """F162 (was S2-GAP-1, spend leg): with a price configured,
        executed calls accrue spend and a tiny max_spend_per_run
        ceiling trips."""
        run, ident = self._run({"max_spend_per_run": 0.000001,
                                "price_per_1k_tokens": 0.002})
        ex = run["executor"]
        statuses = [self._api(ex, ident, i)["status"] for i in range(10)]
        self.assertGreater(ex._spend_used, 0.0,
                           "no spend accrued from executed calls")
        self.assertIn("denied", statuses,
                      "max_spend_per_run never tripped over 10 calls")

    def test_call_kwarg_usage_cannot_inflate_or_deflate(self):
        """An agent cannot forge its usage via call kwargs: ``_usage``,
        ``_tokens_used`` and ``_spend_used`` passed as kwargs are
        ignored — accrual reads the governed-minted RESULT usage, never
        the call. F162: accrual is wired, so the assertion is now that
        the accrued total equals the minted amount (small), not the
        forged 10**12."""
        run, ident = self._run({"max_tokens_per_run": 10**9,
                                "max_spend_per_run": 10**9})
        ex = run["executor"]
        r = ex.call(ident, "api_call",
                    endpoint="https://synthetic.local/forge",
                    _usage={"tokens": 10**12, "spend": 10**12},
                    _tokens_used=10**12, _spend_used=10**12)
        self.assertEqual(r["status"], "executed", r)
        self.assertLess(ex._tokens_used, 1000,
                        "forged _usage kwarg inflated the meter: %d"
                        % ex._tokens_used)
        self.assertEqual(ex._spend_used, 0.0)

    # -- absent / malformed config -----------------------------------------

    def test_absent_budgets_default_enforced(self):
        """F162: no budgets: section -> the DEFAULT action ceiling
        applies (absent is default-enforced, never silently
        unlimited)."""
        run, ident = self._run(None)
        ex = run["executor"]
        statuses = [self._api(ex, ident, i)["status"]
                    for i in range(205)]
        self.assertIn("denied", statuses)
        denied = [self._api(ex, ident, 999)]
        self.assertEqual(denied[0]["status"], "denied", denied[0])
        self.assertEqual(denied[0]["policy_id"], "budget-exceeded",
                         denied[0])
        # The guard engages on the default: the action counter tracks.
        self.assertGreater(ex._budget_actions, 0)

    def test_absent_individual_keys_unenforced(self):
        """A budgets: section with only one key leaves the other
        dimensions unenforced (token/spend ceilings stay
        deployment-configured; only the action ceiling has a
        default)."""
        run, ident = self._run({"max_actions_per_run": 100})
        ex = run["executor"]
        for i in range(8):
            r = self._api(ex, ident, i)
            self.assertEqual(r["status"], "executed", r)
        # Tokens/spend have no ceiling configured: accrual still runs
        # (F162 wires it) but no denial follows.
        self.assertGreater(ex._tokens_used, 0)

    def test_unknown_budget_key_fails_closed_at_load(self):
        p = self.tmp / "bad_budget.yaml"
        p.write_text(_policy_text({"max_nope_per_run": 3}),
                     encoding="utf-8")
        with self.assertRaises(ValueError) as cm:
            PolicyEngine(str(p))
        self.assertIn("unknown key", str(cm.exception))

    def test_negative_budget_value_fails_closed_at_load(self):
        p = self.tmp / "neg_budget.yaml"
        p.write_text(_policy_text({"max_tokens_per_run": -1}),
                     encoding="utf-8")
        with self.assertRaises(ValueError) as cm:
            PolicyEngine(str(p))
        self.assertIn("non-negative", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
