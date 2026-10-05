# Dead-controls allowlist (R16 / Bernstein #4645 + #5505)

This file excuses orphans from the dead-controls gate
(`evals/no_dead_controls.py`). It is the ONLY way to excuse dead
surface, and every line of it is machine-checked.

## Rules (enforced by the gate; this prose is not the enforcement)

- An **orphan module** (no live importer, not a verified entry point) or a
  **dead decision code** (registered, never raised in a reached module)
  fails the gate unless it has an Active entry here.
- Every Active entry needs:
  - `kind:` -- `module` or `code`.
  - `name:` -- the dotted module or the exact decision code.
  - `reason:` -- a WRITTEN reason, at least 20 characters. Placeholders
    ("todo", "legacy", "will fix") fail the gate.
  - exactly ONE of:
    - `finding:` -- an `FNNN` present in `evals/FINDINGS.md` (the orphan
      is tracked as / fixed under a real finding), or
    - `expiry:` -- `YYYY-MM-DD` in the future (the orphan must be
      covered or deleted by this date; a past expiry fails the gate).
- An Active entry whose module is now imported (or whose code is now
  raised, or which no longer exists) FAILS the gate: remove it and log
  the removal. **The allowlist can only shrink.**
- Removing an entry without a Removed log line (name + wave + reason)
  fails the `--base` shrink check. Deleting an entry's text is not
  removal; moving it to Removed with a reason is.
- New Active entries are admitted ONLY through the finding-or-expiry
  ritual above -- never silently, never "temporarily".

## Active

- kind: code | name: honesty-mutant-inconclusive | reason: Registered for the forcing-honesty INCONCLUSIVE mutant outcome (mutant did not build/run; never folded into gaps), but tools/forcing_honesty.py's classify() returns the bare "INCONCLUSIVE" vocabulary string and never emits the taxonomy code -- verified no production raise site and no dynamic construction. The expiry forces the decision: wire the code into the report path or retire the registration. | expiry: 2026-11-15 | added: wave-338

## Removed

(none yet)
