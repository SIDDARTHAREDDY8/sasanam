"""S4 (K-045): total-step budget tests (gov/executor.py).

Verifies the S4 guard:

* The counter counts every call() ATTEMPT that passes the ledger
  gate — executed, policy-denied, role-denied, and queued attempts
  all consume step budget (it is a budget on run activity and log
  growth).
* The ``>`` convention: exactly N calls are allowed; call N+1 is
  denied (matches the existing write/delete guard convention).
* Denials audit ``policy_id="step-budget"`` / flag
  ``"step_budget_exceeded"``.
* Absent ``run_limits.max_tool_calls_per_run`` = DEFAULT ceiling
  enforced (F162: absent is default-enforced, never silently
  unlimited); malformed sections fail the policy load closed.

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


def _policy_text(run_limits=None, budgets=None):
    rl_yaml = ""
    if run_limits is not None:
        rl_yaml = "run_limits:\n"
        for k, v in run_limits.items():
            rl_yaml += "  %s: %s\n" % (k, v)
    budgets_yaml = ""
    if budgets is not None:
        budgets_yaml = "budgets:\n"
        for k, v in budgets.items():
            budgets_yaml += "  %s: %s\n" % (k, v)
    return """\
version: 2
roles:
  worker: [api_call, delete_file]
rate_limit:
  max_sends_per_run: 100
  max_egress_bytes_per_run: 262144
egress:
  domain_allowlist: [synthetic.local, localhost]
%s%spolicies:
  - id: test-allow-api
    effect: allow
    match:
      tool: [api_call]
    reason: Test policy allows api_call.
  - id: test-queue-deletes
    effect: require_approval
    match:
      tool: [delete_file]
    reason: Test policy queues deletes.
""" % (rl_yaml, budgets_yaml)


def _tmpdir(prefix):
    base = Path("/tmp/gov-run")
    base.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=str(base)))


class TestStepBudget(unittest.TestCase):
    def setUp(self):
        self.tmp = _tmpdir("govs4-")
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def _run(self, run_limits=None, tempo=None, budgets=None):
        p = self.tmp / ("policy_%d.yaml" % id(self))
        text = _policy_text(run_limits, budgets)
        if tempo is not None:
            text = text.replace("version: 2\n",
                                "version: 2\ntempo:\n" +
                                "".join("  %s: %s\n" % kv
                                        for kv in tempo.items()), 1)
        p.write_text(text, encoding="utf-8")
        run = make_run(policy_path=str(p))
        ident = run["mint_identity"]("w1", "worker", "acme")
        return run, ident

    def test_counter_counts_every_attempt(self):
        """Executed, policy-queued, and role-denied attempts ALL
        consume step budget (denied/queued included)."""
        run, ident = self._run({"max_tool_calls_per_run": 100})
        ex = run["executor"]
        r1 = ex.call(ident, "api_call",
                     endpoint="https://synthetic.local/a")   # executed
        r2 = ex.call(ident, "delete_file",
                     path="gone.txt")                        # queued
        r3 = ex.call(ident, "send_email", to="x@synthetic.local",
                     subject="t", body="b")                  # role-denied
        self.assertEqual(r1["status"], "executed", r1)
        self.assertEqual(r2["status"], "queued", r2)
        self.assertEqual(r3["status"], "denied", r3)
        self.assertEqual(r3["policy_id"], "role-allowlist", r3)
        self.assertEqual(ex._total_calls, 3,
                         "attempts must be counted regardless of outcome")

    def test_gt_convention_exactly_n_allowed(self):
        """``>`` (not ``>=``): exactly N calls are allowed; call N+1
        is denied."""
        run, ident = self._run({"max_tool_calls_per_run": 3})
        ex = run["executor"]
        for i in range(3):
            r = ex.call(ident, "api_call",
                        endpoint="https://synthetic.local/g%d" % i)
            self.assertEqual(r["status"], "executed", r)
        r4 = ex.call(ident, "api_call",
                     endpoint="https://synthetic.local/g3")
        self.assertEqual(r4["status"], "denied", r4)
        self.assertEqual(r4["policy_id"], "step-budget", r4)

    def test_denial_audits_step_budget_exceeded(self):
        """A step-budget denial is audit-visible with the
        step_budget_exceeded flag and step-budget policy id."""
        run, ident = self._run({"max_tool_calls_per_run": 1})
        ex = run["executor"]
        ex.call(ident, "api_call", endpoint="https://synthetic.local/1")
        denied = ex.call(ident, "api_call",
                         endpoint="https://synthetic.local/2")
        self.assertEqual(denied["status"], "denied")
        entries = [e for e in run["read_log"]()
                   if e.get("policy_id") == "step-budget"]
        self.assertTrue(entries, "expected a step-budget audit entry")
        last = entries[-1]
        self.assertEqual(last["decision"], "denied")
        self.assertEqual(last["flag"], "step_budget_exceeded")
        self.assertIn("step budget", last["reason"])

    def test_absent_key_default_enforced(self):
        """F162: no run_limits.max_tool_calls_per_run -> the DEFAULT
        step budget applies (absent is default-enforced, never silently
        unlimited); the counter still tracks attempts. The tempo wire
        is raised out of the way here so the step budget is what
        trips (the tight loop would otherwise hit tempo first — the
        designed layering)."""
        run, ident = self._run(
            None, tempo={"max_read": 10**6,
                         "max_write": 10**6,
                         "max_egress": 10**6},
            budgets={"max_actions_per_run": 10000})
        ex = run["executor"]
        for i in range(405):
            r = ex.call(ident, "api_call",
                        endpoint="https://synthetic.local/u%d" % i)
            if r["status"] == "denied":
                break
        else:
            self.fail("default step budget never engaged over 405 calls")
        self.assertEqual(r["policy_id"], "step-budget", r)
        self.assertEqual(ex._total_calls, 401)

    def test_zero_step_budget_denies_first_attempt(self):
        """max_tool_calls_per_run=0 is a valid config meaning 'no
        calls': the first attempt already exceeds it."""
        run, ident = self._run({"max_tool_calls_per_run": 0})
        r = run["executor"].call(ident, "api_call",
                                 endpoint="https://synthetic.local/z")
        self.assertEqual(r["status"], "denied", r)
        self.assertEqual(r["policy_id"], "step-budget", r)

    def test_unknown_run_limits_key_fails_closed_at_load(self):
        p = self.tmp / "bad_rl.yaml"
        p.write_text(_policy_text({"max_nope_per_run": 3}),
                     encoding="utf-8")
        with self.assertRaises(ValueError) as cm:
            PolicyEngine(str(p))
        self.assertIn("unknown key", str(cm.exception))

    def test_malformed_run_limits_value_fails_closed_at_load(self):
        for bad in ("-1", "many", "true"):
            with self.subTest(value=bad):
                p = self.tmp / ("bad_rl_%s.yaml"
                                % bad.replace("-", "neg"))
                p.write_text(
                    _policy_text({"max_tool_calls_per_run": bad}),
                    encoding="utf-8")
                with self.assertRaises(ValueError):
                    PolicyEngine(str(p))


if __name__ == "__main__":
    unittest.main()
