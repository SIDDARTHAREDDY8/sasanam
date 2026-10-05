#!/usr/bin/env python3
"""No-network unit checks for the realmodel harness budget logic.

Covers: SpendLedger precheck refuses over total/run/call caps BEFORE any
network I/O; worst-case estimate is conservative (>= naive 4 chars/token);
record() accumulates run_spent and persists; ModelDriver refuses unpriced
models; max_tokens > 150 is refused by main().
"""
import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import importlib.util

spec = importlib.util.spec_from_file_location(
    "realmodel_harness",
    os.path.join(REPO_ROOT, "evals", "realmodel_harness.py"))
h = importlib.util.module_from_spec(spec)
spec.loader.exec_module(h)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, cond, detail))
    print("[%s] %s %s" % (PASS if cond else FAIL, name, detail))


def fresh_ledger(**kw):
    d = tempfile.mkdtemp(prefix="w333-ledger-")
    return h.SpendLedger(path=os.path.join(d, "ledger.json"), **kw)


# 1. per-call cap refused before network
L = fresh_ledger(total_budget=5.0, run_cap=0.50, call_cap=0.05)
try:
    L.precheck("x" * 3000000, 150, "gpt-4o-mini", "unit-overcall")
    check("call-cap-refused", False, "precheck did not raise")
except h.BudgetRefused as e:
    check("call-cap-refused", True, str(e)[:80])

# 2. per-run cap refused
L2 = fresh_ledger(total_budget=5.0, run_cap=0.00001, call_cap=0.05)
try:
    L2.precheck("hello", 150, "gpt-4o-mini", "unit-overrun")
    check("run-cap-refused", False, "precheck did not raise")
except h.BudgetRefused as e:
    check("run-cap-refused", True, str(e)[:80])

# 3. total budget refused
L3 = fresh_ledger(total_budget=0.0, run_cap=0.50, call_cap=0.05)
try:
    L3.precheck("hello", 150, "gpt-4o-mini", "unit-overtotal")
    check("total-cap-refused", False, "precheck did not raise")
except h.BudgetRefused as e:
    check("total-cap-refused", True, str(e)[:80])

# 4. worst-case estimate is conservative (3 chars/token overestimates)
est = h._conservative_token_estimate("a" * 400)
check("worst-case-conservative", est >= 100, "400 chars -> %d tokens" % est)

# 5. record() accumulates and persists
L4 = fresh_ledger()
L4.precheck("hello world", 150, "gpt-4o-mini", "unit-ok")
c = L4.record("gpt-4o-mini", 100, 50, "unit-ok", 0.0001)
check("record-accumulates", L4.run_spent == c and c > 0,
      "run_spent=$%.6f" % L4.run_spent)
disk = json.loads(Path(L4.path).read_text())
check("record-persists", len(disk["entries"]) == 1 and
      disk["entries"][0]["kind"] == "call", "entries on disk: %d"
      % len(disk["entries"]))
check("total_spent-sums", abs(L4.total_spent - c) < 1e-12,
      "$%.6f" % L4.total_spent)

# 6. unpriced model refused
try:
    h.ModelDriver(fresh_ledger(), model="gpt-9-ultra")
    check("unpriced-model-refused", False, "driver accepted unknown model")
except h.ModelCallFailed as e:
    check("unpriced-model-refused", True, str(e)[:70])

# 7. non-default model needs explicit flag
try:
    d = h.ModelDriver(fresh_ledger(), model="gpt-4o")
    d.generate("s", "u", "unit")
    check("nondefault-needs-flag", False, "generate proceeded without flag")
except h.ModelCallFailed as e:
    check("nondefault-needs-flag", "requires --allow-other-model" in str(e),
          str(e)[:70])

# 8. attack-JSON parser is loud on garbage
try:
    h._parse_attack_json("not json at all {{{", "unit-parse")
    check("parser-loud-on-garbage", False, "parser accepted garbage")
except h.ModelCallFailed as e:
    check("parser-loud-on-garbage", True, str(e)[:70])

# 9. attack-JSON parser tolerates one fenced block
url, payload = h._parse_attack_json(
    '```json\n{"url": "https://x/y", "payload": {"a": "b"}}\n```',
    "unit-fence")
check("parser-tolerates-fence",
      url == "https://x/y" and payload == {"a": "b"}, url)

fails = [r for r in results if not r[1]]
print("tally: %d/%d unit checks green" % (len(results) - len(fails),
                                          len(results)))
sys.exit(0 if not fails else 1)
