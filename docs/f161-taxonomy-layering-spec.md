# F161 layering fix — SAR severity taxonomy ownership spec

## Problem Statement

The product layer hard-depends on the eval-harness layer: importing
`gov.safeguard_bundle` (and therefore the flagship safeguard evidence
surface) triggers a top-level `from evals.safeguard_results import ...`
inside `gov.safeguard_benchmark`. From a source checkout this silently
works because `evals/` happens to be importable; from an installed wheel
(where `evals/` is not packaged) the import fails. The dependency direction
is inverted: the eval harness should depend on product schema data, never
the reverse.

## Solution

The SAR severity taxonomy (the incident severity bands and weights the
Safeguard Assessment Report is graded against) is product schema data and
moves into the product layer. The battery-artifact loader stays in the eval
harness and is reached only lazily at its single use site. The eval-harness
module keeps re-exporting the taxonomy names so every existing importer
keeps working unchanged.

## User Stories

1. As a ship operator, I want `import gov.safeguard_bundle` to succeed
   from an installed wheel without `evals/` on the path, so that the
   safeguard surface can ship as a package.
2. As an evaluator author, I want to keep importing the taxonomy names
   and the battery loader from `evals.safeguard_results` exactly as today,
   so that no harness script or break battery needs editing.
3. As a SAR consumer, I want the severity bands, weights, required
   categories, and uncovered set to keep identical values and identities,
   so that reports rendered before and after the fix are comparable.
4. As a future reviewer, I want the layering rule "gov/ never imports
   evals/ at module scope" to be enforced by a regression test, so that
   the inversion cannot silently return.
5. As a standards-mapping author, I want the taxonomy reachable as a
   small product-layer module without pulling in benchmark-rendering
   logic, so that evidence exports can reuse the schema datum.

## Implementation Decisions

- New product-layer module owns the taxonomy: a dedicated
  `safeguard_taxonomy` module under `gov/`, rather than constants inlined
  in `gov/safeguard_benchmark`. Rationale: the constants are SAR schema
  data, not benchmark-primitive behavior; a small deep module gives the
  re-export shim a correct-direction dependency (harness depends on
  product) and lets evidence-export modules reuse the schema datum without
  importing the report renderer. One canonical owner, single seam.
- Canonical names moved: `CATEGORY_SEVERITY`, `SEVERITY_WEIGHTS`,
  `UNCOVERED_CATEGORIES`, `REQUIRED_CATEGORIES` — values byte-identical,
  container types unchanged (dict / dict / frozenset / frozenset), prose
  comments carried over.
- `gov/safeguard_benchmark` imports the taxonomy from the new product
  module at module scope (product-internal, allowed) and reaches
  `load_battery_results` via a function-level lazy import at its only call
  site inside the report builder — the established pattern already used
  for the lazy import at the risk-section seam.
- `evals/safeguard_results` keeps `load_battery_results` as the canonical
  definition and re-exports the four taxonomy names from the product
  module, keeping import order fail-safe: the harness module sets the
  staging deployment mode before any `gov` import.
- Existing importers untouched: the benchmark test module and any
  harness scripts keep importing from `evals.safeguard_results`.
- No taxonomy value changes, no battery-behavior changes, no SAR schema
  changes — pure layering move.

## Testing Decisions

- Red-first regression test at the module seam: block `evals` in
  `sys.modules` (and purge already-imported `evals.*` entries), then
  `import gov.safeguard_bundle` and `import gov.safeguard_benchmark`.
  Must FAIL on the unfixed tree (ImportError from the top-level harness
  import), PASS after. This test is the layering invariant.
- Identity assertions: the names re-exported from `evals.safeguard_results`
  are the same objects as the product module's (no silent fork).
- Value-parity check: rendered SAR values pre/post fix must match; covered
  by running the existing benchmark/bundle test modules unchanged.
- Module-level deployment-mode declaration after imports in the new test
  (wave-95 convention).
- The new test module lives with the other regression tests and runs under
  both a normal environment and a clean (`env -u GOV_DEPLOYMENT_MODE`)
  environment, with the canonical venv.

## Out of Scope

- Changing taxonomy values, adding/removing categories, or re-banding
  severities.
- Moving any other harness functionality into `gov/`.
- Packaging changes (pyproject/wheel contents) — owned by the packaging
  lane; this fix only removes the code-level blocker.
- Editing `evals/FINDINGS.md` or `BUILD_LOG.md` — owned by the W1
  coordinator.

## Further Notes

- Residual scan: no other `gov/` module imports `evals` at top level
  (verified by grep over `gov/*.py`).
- The harness scripts that import `gov.safeguard_benchmark` (e.g. break
  batteries) exercise the new direction incidentally — harness depends on
  product — and are unaffected.
