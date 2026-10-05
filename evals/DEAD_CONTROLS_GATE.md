# Dead-controls gate (R16) — merge-coordinator wiring

**Gate:** `evals/no_dead_controls.py` · **Allowlist:** `evals/dead_controls_allowlist.md`
**Regression:** `evals/w338_deadctrl_probes.py` (0 BREAK / 11 HELD)
**Origin:** wave-338 lane 3 (Bernstein R16 STEAL: #5053, #4645, #5505).

## What it enforces

No dead policy controls ship. Every importable `gov/` module must be
imported by a live root (`tests/`, `evals/`, `demo/`, `tools/`,
`examples/`), or be a verified entry point, or be allowlisted. Every
decision code registered in `gov/decision_codes.py` must be raised in a
reached production module (or `tools/`/`demo/`), or be allowlisted.
Imports only — docstrings, comments, and string mentions reach nothing;
reachability is a fixpoint (a module imported only by an unreached
module stays unreached).

Entry points: an unimported `__main__` module is live IFF its invocation
is documented and checkable (`pyproject.toml [project.scripts]` target
or a `python -m <dotted>` literal in docs/docstrings/demos). An
undocumented `__main__` block is an orphan.

Allowlist (Bernstein #4645 + #5505): the ONLY excuse for dead surface.
Each active entry needs a written reason (>= 20 chars) AND exactly one
of `finding: FNNN` (present in `evals/FINDINGS.md`) or `expiry:
YYYY-MM-DD` (future). Newly-reachable entries, stale entries, expired
entries, and missing reasons all fail. **The allowlist can only
shrink:** removing an entry without a `Removed` log line (name + wave +
reason) fails the `--base` check.

## How the merge coordinator runs it

Add a row to the merge report's gate table:

| Dead-controls | PASS (`evals/no_dead_controls.py --base <base-commit>`, exit 0) |

Commands (fresh `/var/tmp/gNNN-*` TMPDIR per the standing rules):

```
mkdir -p /var/tmp/g338-deadctrl-gate
TMPDIR=/var/tmp/g338-deadctrl-gate ~/workspace/.gov-venv/bin/python \
    evals/no_dead_controls.py --base <base-commit>
TMPDIR=/var/tmp/g338-deadctrl-batt ~/workspace/.gov-venv/bin/python \
    evals/w338_deadctrl_probes.py
```

- Exit 0 = PASS. Exit 1 = REFUSE (dead surface; the report names it).
  Exit 2 = gate-internal error (never a pass; investigate, do not ship).
- `--base` enables the shrink-only check against the base commit's
  allowlist. Omit it only when git history is unavailable; the remaining
  rules still run.
- The gate is stdlib-only, $0 spend, ~40s on the full tree. It does not
  execute repo code (AST only).

## When the gate goes red on a lane tree

1. Read the VIOLATION lines: they name the orphan module or dead code.
2. Decide, in order: **cover it** (import it / raise the code in
   production), **delete it** (dead code deleted needs no allowlist),
   or **allowlist it** (written reason + finding-or-expiry, per the
   rules in the allowlist file's header).
3. Never silence the gate by widening a rule. A rule change needs its
   own red-first justification in the lane report.

## Current honest state (wave-338)

- 504 importable gov modules; 503 reached; 1 verified entry point
  (`gov.approve` — the documented `python -m gov.approve` CLI shim).
- 2124 registered codes; 2123 live; 1 dead and allowlisted:
  `honesty-mutant-inconclusive` (reason + expiry 2026-11-15 recorded in
  the allowlist; the tool's `classify()` returns the bare
  `"INCONCLUSIVE"` vocabulary string and never emits the taxonomy code).
- Allowlist: 1 active, 0 removed.
