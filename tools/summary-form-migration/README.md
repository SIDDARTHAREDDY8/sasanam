# Summary-form migration tooling (canonical reference)

Consolidated reference copies of the mechanical codemod + migration
driver for the probe-line summary-form rollout (canonical form:
`[VERDICT] pid: note` via `evals/probe_lines.emit`).

Provenance:
- wave-309 lane F: original codemod + driver; `_summary_print_span`
  paren-aware fix.
- wave-310 lane D: generalized S2 loop pattern, summary-count var
  extraction, driver `summary_counts` name prefix.
- wave-311 lane B: list-name-aware coherence snippet; driver summary
  prefix class allows spaces.
- wave-312 lane B: TREE-anchor extension, generalized S3 loop,
  HELD-first summary support, non-canonical verdict refusal,
  unified coherence snippet. Rollout total 67/693.

The mechanical pool is EXHAUSTED as of wave-312: the 86 remaining
candidates all need policy decisions (GAP->? mapping, dict-result
emit, truncation policy) — see BUILD_LOG wave-312. Do not run further
mechanical migrations until those decisions are made.

Usage: `python3 migrate_driver.py <battery-file>...` (verify
before/after counts byte-identical under staging and clean env).
