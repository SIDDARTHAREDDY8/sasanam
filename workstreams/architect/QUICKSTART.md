# Quickstart — from the wheel to a governed run in ~2 minutes

**You need exactly two things:** the wheel file you were given
(`agent_governance-<version>-py3-none-any.whl`) and this file. No
checkout, no PyPI, no network. Python ≥ 3.9.

**Timing:** ~2 minutes end to end (measured 2026-09-25 on a fresh
venv). Everything is synthetic and local — simulated tools, fake data,
no network calls, no real credentials.

**One rule:** run steps 2, 3, and 5 in the **same shell**. The
`GOV_LOG_KEY` export in step 2 must be visible to `gov-demo`,
`gov-verify`, and `gov-report` (they read the same chained log).
Step 7 (attack demo + evidence bundle) self-provisions and does not
need the key; steps 1, 4, and 6 don't either.

---

## 1. Install into a fresh venv (~10 s)

```bash
WHEEL=/path/to/dist/agent_governance-0.2.0-py3-none-any.whl   # ← your wheel's path
python3 -m venv /tmp/gov-qs-venv
/tmp/gov-qs-venv/bin/pip install "$WHEEL"
/tmp/gov-qs-venv/bin/pip list 2>/dev/null | grep -i agent-governance
# agent-governance  0.2.0        (and nothing else: the base is stdlib-only)

# Sanity: every entry point resolves and honors --help.
/tmp/gov-qs-venv/bin/gov-demo --help >/dev/null && echo "gov-demo OK"
for ep in gov-attack-demo gov-approve gov-verify gov-policy-lint gov-policy-export gov-report; do
  /tmp/gov-qs-venv/bin/$ep --help >/dev/null && echo "$ep OK"
done
```

---

## 2. Run the demo in a fresh directory (~5 s)

```bash
mkdir -p /tmp/gov-qs && cd /tmp/gov-qs
# One key for the whole session. gov-demo self-provisions a test key if
# this is unset — but then gov-verify / gov-report in later steps cannot
# check the log (production entry points fail closed with no key).
export GOV_LOG_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")
export GOV_LOG_KEY_EPOCH=test
/tmp/gov-qs-venv/bin/gov-demo
```

Expected tail:

```
[7] Audit summary
  tool_call decisions: denied: 8
  tool_call decisions: queued_pending: 3
  ...
  hash chain: OK (32 entries)

Run directory: /tmp/gov-qs/runs/demo-20260925-013151-343349
Next steps:
  gov-report --rundir /tmp/gov-qs/runs/demo-20260925-013151-343349
  gov-approve --rundir /tmp/gov-qs/runs/demo-20260925-013151-343349 list
```

What happened: a 4-agent pipeline (scout → triage → builder →
publisher) ran through the governance layer. Risky steps were queued
for a human instead of executing; every decision was write-ahead
logged to a hash-chained audit trail.

Each run gets its own directory (microsecond run ids) and its own
egress ledger, so concurrent runs in one directory never collide.

---

## 3. Verify the audit log offline (<1 s)

```bash
RUN_DIR=$(ls -dt runs/*/ | head -1)   # the run you just made
/tmp/gov-qs-venv/bin/gov-verify "$RUN_DIR/actions.jsonl"
# {
#   "broken_seq": null,
#   "entries": 32,
#   "error": null,
#   "ok": true
# }
# exit 0 = chain intact. With the wrong key it fails closed (ok: false).
```

---

## 4. Inspect the human approval queue (<1 s)

```bash
/tmp/gov-qs-venv/bin/gov-approve list   # defaults to the latest run in ./runs
# Approvals for run demo-20260925-013151-343349 (pending: highest risk first):
#   ID: 51d52f4e | agent: publisher-01 | tool: http_post | status: pending | policy: approval-tainted-action | risk: 60 (high)
#     ...
```

This is the step the demo queued instead of executing. A human decides
it — `gov-approve --help` lists the `batch`, `break-glass`, and audit
flows.

---

## 5. Render the audit report (<1 s)

```bash
/tmp/gov-qs-venv/bin/gov-report --rundir "$RUN_DIR"
# wrote /tmp/gov-qs/reports/demo-20260925-013151-343349_audit_report.html
# chain: OK (32 entries)
# findings: 6
```

Markdown + HTML land in `reports/`.

---

## 6. Lint the shipped policy (<1 s)

The canonical policy ships inside the wheel
(`gov/data/default.yaml`); reach it through `importlib.resources` —
no checkout needed:

```bash
POLICY=$(/tmp/gov-qs-venv/bin/python -c "import importlib.resources as r; print(r.files('gov') / 'data' / 'default.yaml')")
/tmp/gov-qs-venv/bin/gov-policy-lint "$POLICY"
# [info   ] overly_broad_allow   allow-reads                  allow constrained by tool name only ...
# [info   ] overly_broad_allow   allow-api                    allow constrained by tool name only ...
# 2 finding(s): 0 error(s), 0 warning(s)
```

The exit code is 1 here — that means "findings present", not
"failure": 0 errors, 0 warnings, 2 informational notes.

---

## 7. (Optional) the attack demo + the evidence bundle

```bash
# Same shell (key still exported). The attack demo runs anywhere:
/tmp/gov-qs-venv/bin/gov-attack-demo
# RESULT: 4 attack attempts blocked, 0 allowed, 1 tampering detected.

# The evidence demo in a fresh directory:
mkdir -p /tmp/gov-qs-ev && cd /tmp/gov-qs-ev
/tmp/gov-qs-venv/bin/python -m demo.evidence_demo
# ...
# AUDIT VERDICT
#   2 of 2 anchored epoch(s) verified ANCHORED; 0 operator-attested-only.
#   Attribution: PASS. Stopped attack: PASS.
#   Open epoch: 2 record(s) unverifiable until the next anchor.
#
# Evidence bundle: /tmp/gov-qs-ev/runs/evidence-20260925-013217-348604/evidence

# The independent verifier holds no copy of the chain's HMAC key:
/tmp/gov-qs-venv/bin/python -m demo.verify_evidence --bundle $(ls -dt runs/*/ | head -1)evidence
# (same AUDIT VERDICT, plus the honest-boundaries statement)
```

---

## Known gotchas (verified 2026-09-25 against the 0.2.0 wheel)

1. **PyPI is not a source.** Install from the wheel you were given.
2. **One shell for the whole session.** `GOV_LOG_KEY` must be exported
   in the same shell for `gov-demo`, `gov-verify`, and `gov-report`.
   A new shell needs a fresh export (or re-export of the same key).
3. **Demos write into the current directory** (`runs/`, `reports/`).
   Work in a fresh directory per scenario.
4. **`gov-policy-lint` exits 1 on info-level findings.** Read the
   summary line: `0 error(s), 0 warning(s)` is the passing state.
5. **`gov-policy-export` refuses the shipped policy** (exit 1): the
   default policy uses `require_approval` without bridge bindings and
   stateful match keys, which have no Cedar/Dogwood equivalent. The
   refusal is the feature — it never silently drops semantics.
6. **The demos are synthetic** (simulated tools, fake data). The
   enforcement pipeline — identity, policy, approvals, hash-chained
   audit — is real.
