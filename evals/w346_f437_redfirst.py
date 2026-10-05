"""Red-first for F437 (LOW, OPEN): the policy-delta risk gate does not
model ladder `mode` changes.

F437: gov/policy_delta_gate.analyze_policy_delta reports verdict
"pass" with zero findings for a deny rule flipped to `mode: observe`
-- but the flip genuinely weakens enforcement (the observe-mode deny
carries no authority: the secret read goes deny -> allow, and the
adaptive-adversary cred campaign breaks silently).

This script prints BREAK on the open tree (delta gate blind) and is
the re-file record per the standing red-first rule. It must NOT be
quietly patched into the delta gate; a closure lane re-verifies it.
"""

import os
import re
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import policy_delta_gate as _pdg  # noqa: E402
from gov.policy import PolicyEngine  # noqa: E402


def main():
    base = open(os.path.join(REPO_ROOT, "policies", "default.yaml")).read()
    pat = re.compile(r"(  - id: deny-secret-reads\n(?:.*\n)*?    effect: deny\n)")
    weak, n = pat.subn(lambda m: m.group(1) + "    mode: observe\n",
                       base, count=1)
    assert n == 1

    # 1. The delta gate's verdict on the weakening.
    report = _pdg.analyze_policy_delta(base, weak)
    delta_blind = (report["verdict"] == "pass"
                   and not report["risk_findings"])

    # 2. The weakening is genuine (engine verdict flips deny -> allow).
    probe = {"tool": "read_file", "role": "researcher",
             "args": {"path": "config/.env"}}
    before = PolicyEngine(
        os.path.join(REPO_ROOT, "policies", "default.yaml")).evaluate(probe)
    tmp = "/var/tmp/g346-f437-weak.yaml"
    open(tmp, "w").write(weak)
    after = PolicyEngine(tmp).evaluate(probe)
    genuinely_weaker = (before.effect == "deny" and after.effect == "allow")

    if delta_blind and genuinely_weaker:
        print("F437 BREAK: delta gate verdict=pass, 0 findings on a "
              "deny->observe flip that weakens enforcement "
              "(deny -> allow)")
        return 1
    print("F437 HELD: delta gate models mode changes "
          "(verdict=%s findings=%d)" % (report["verdict"],
                                        len(report["risk_findings"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
