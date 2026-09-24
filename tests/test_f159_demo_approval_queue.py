"""F159 regression: demo/run_demo.py must not hardcode the approval queue.

The flagship quickstart crashed on master with KeyError: 'api_call' because
section [5] hardcoded "approve the 6th api_call" while the current policy
DENIES the scout's api_call — demo-vs-policy drift.

Seams (highest first):
  1. The demo script as a whole, run as a subprocess in a fresh temp cwd
     against the CURRENT policy. Asserts exit 0, hash chain OK, and
     approval decisions recorded. RED on master (KeyError), GREEN after fix.
  2. The demo's queue-lookup helper: returns the queued record for a tool
     that IS queued; raises SystemExit with an honest message naming the
     missing tool when the queue lacks it — never KeyError, never a silent
     skip. A demo that approves nothing is a lie.
"""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
_REPO_MAIN = os.path.dirname(_TESTS_DIR)  # .../agent-governance-demo-main

RUN_DEMO = os.path.join(_REPO_MAIN, "demo", "run_demo.py")


def _load_run_demo():
    # Load demo/run_demo.py as a module without executing main(): the
    # module's only top-level effects are env staging defaults, a
    # sys.path insert, and gov imports — all inert.
    spec = importlib.util.spec_from_file_location("run_demo_f159", RUN_DEMO)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DemoApprovalQueueDriftTest(unittest.TestCase):
    """The demo's human-review step must derive its decisions from the
    actual pending-approval queue, not a hardcoded tool name."""

    def fresh_cwd(self):
        d = tempfile.mkdtemp(prefix="test-f159-demo-")
        self.addCleanup(shutil.rmtree, d, True)
        return d

    def test_demo_completes_end_to_end_on_current_policy(self):
        # F159: on master this crashes with KeyError: 'api_call' because
        # the policy denies the scout's api_call and the script hardcodes
        # "approve the 6th api_call".
        d = self.fresh_cwd()
        proc = subprocess.run(
            [sys.executable, RUN_DEMO],
            cwd=d, capture_output=True, text=True, timeout=300)
        self.assertEqual(
            proc.returncode, 0,
            "demo/run_demo.py crashed on the current policy:\nSTDOUT:\n%s\n"
            "STDERR:\n%s" % (proc.stdout[-4000:], proc.stderr[-4000:]))
        self.assertIn("hash chain: OK", proc.stdout)
        runs_dir = os.path.join(d, "runs")
        runs = [p for p in os.listdir(runs_dir)
                if os.path.isdir(os.path.join(runs_dir, p))]
        self.assertEqual(len(runs), 1)
        actions = os.path.join(d, "runs", runs[0], "actions.jsonl")
        self.assertTrue(os.path.isfile(actions))
        decisions = [l for l in open(actions, encoding="utf-8")
                     if '"event": "approval_decision"' in l]
        # The hero path approves one queued action and rejects one
        # out-of-bounds action; the webhook post stays pending. A demo
        # that approves nothing is a lie — at least one approval and
        # one rejection must be on record.
        kinds = [l for l in decisions]
        self.assertTrue(any('"decision": "approved"' in l for l in kinds),
                        "no approved decision recorded")
        self.assertTrue(any('"decision": "rejected"' in l for l in kinds),
                        "no rejected decision recorded")

    def test_queue_lookup_returns_queued_record(self):
        mod = _load_run_demo()
        pending = [
            {"id": "aid-1", "tool": "write_file", "agent_id": "b-01",
             "policy_reason": "needs approval"},
            {"id": "aid-2", "tool": "send_email", "agent_id": "p-01",
             "policy_reason": "needs approval"},
        ]
        self.assertEqual(mod.find_pending_by_tool(pending, "send_email"),
                         "aid-2")
        self.assertEqual(mod.find_pending_by_tool(pending, "write_file"),
                         "aid-1")

    def test_queue_lookup_fails_loudly_when_tool_not_queued(self):
        # F159 honesty rule: when the policy queues nothing approvable
        # for a required decision, the demo must fail LOUDLY — never
        # KeyError (old bug), never silently skip.
        mod = _load_run_demo()
        pending = [{"id": "aid-9", "tool": "http_post", "agent_id": "p-01",
                    "policy_reason": "needs approval"}]
        with self.assertRaises(SystemExit) as cm:
            mod.find_pending_by_tool(pending, "api_call")
        msg = str(cm.exception)
        self.assertIn("api_call", msg)
        self.assertIn("queued", msg)


if __name__ == "__main__":
    unittest.main()
