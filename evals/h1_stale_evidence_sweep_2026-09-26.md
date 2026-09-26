# H1 stale-evidence sweep — 2026-09-26 (Wave-117 Lane A)

Scope: re-run rows 1–6 break batteries **unmodified** against the current tree,
in both deployment modes, with pre-created dedicated TMPDIRs. Freshness check
on every previously documented verdict.

## Tree state

- Working tree: `/home/hatch/workspace/agent-governance-demo/agent-governance-demo-main`
  (no `.git`; remote HEAD stated as `2b12357`).
- A sibling Wave-117 lane edited `gov/executor.py` concurrently during this lane
  (mtimes 07:54:30, 07:57:24 UTC); final runs below are against the settled tree
  (`gov/executor.py` md5 `92b512f93201…`, stable from ~07:58:32 UTC 2026-09-26).
- Earlier same-day runs against the pre-07:54:30 tree gave identical verdicts;
  the settled-tree re-run is authoritative.

## Commands (per battery, both envs)

```bash
cd /home/hatch/workspace/agent-governance-demo/agent-governance-demo-main
mkdir -p /tmp/la2_e1_gap1   # … one dedicated TMPDIR per battery per env
PY=~/workspace/.gov-venv/bin/python
TMPDIR=/tmp/la2_e1_gap1 $PY evals/gap1mem_break.py            # env 1
TMPDIR=/tmp/la2_e2_gap1 env -u GOV_DEPLOYMENT_MODE $PY evals/gap1mem_break.py  # env 2
# … repeated for gap2_buslineage_break, gap3_approver_shield,
#   eval_harness_sandbag_break, gap5_reverify_break, identity_covert_break
```

Python: `~/workspace/.gov-venv/bin/python` (AGENTS.md canonical-venv rule).

## Results (settled tree, `92b512f93201`)

| Row | Battery | Env 1 | Env 2 | Prior documented | Drift? |
|-----|---------|-------|-------|------------------|--------|
| 1 | `gap1mem_break` | 0 BREAK / 9 HELD / 0 ERROR | 0 BREAK / 9 HELD / 0 ERROR | 0/9/0 | none |
| 2 | `gap2_buslineage_break` | 6 tests OK | 6 tests OK | 0 BREAK / 6 HELD / 0 ERROR | none |
| 3 | `gap3_approver_shield` | 0 BREAK / 10 HELD / 0 ERROR | 0 BREAK / 10 HELD / 0 ERROR | 0/10/0 | none |
| 4 | `eval_harness_sandbag_break` | 0 BREAK / 7 HELD / 0 ERROR | 0 BREAK / 7 HELD / 0 ERROR | 0/7/0 | none |
| 5 | `gap5_reverify_break` | 0 BREAK / 9 HELD / 0 ERROR | 0 BREAK / 9 HELD / 0 ERROR | 0/9/0 | none |
| 6 | `identity_covert_break` | 0 BREAK / 13 HELD / 2 CONTROL / 0 ERROR | 0 BREAK / 13 HELD / 2 CONTROL / 0 ERROR | 0/13/2/0 | none |

All deterministic-across-2-runs flags True internally. Zero regressions, zero
new findings. No stale evidence remains for rows 1–6.

## Notes

- `gap2_buslineage_break` is unittest-style (`Ran 6 tests … OK`); the
  "0 BREAK / 6 HELD / 0 ERROR" mapping is the battery's documented verdict
  vocabulary, not a re-run artifact.
- The sibling lane's `_record_upload(content_hashes=…)` refactor (H3) landed
  between the two sweep generations; the settled-tree re-run above already
  includes it. No verdict moved.

Signed-off-by: SIDDHARTHA REDDY <75976672+SIDDHARTHAREDDY8@users.noreply.github.com>
