# Green-check contract (normative)

Wave-305. This contract is fail-closed test infrastructure: a broken
dependency battery must fail the check loudly, never pass as "0 BREAKs".

## Rationale

The wave-303 merge dropped the entire module header of
`evals/w302_redteam_probes.py` (`NameError: unittest` on import), yet the
inner green checks of adjacent batteries passed it vacuously:
`w303_redteam_probes.py`'s allowlist check counts `[BREAK]` lines, and a
traceback emits none, so a broken child read as "0 BREAK (all expected) /
rest held"; `w303_f382f383_probes.py`'s check recorded "no output" as an
ambiguous BREAK. A green check that cannot tell "dependency ran green"
from "dependency never ran" is worse than no check — it certifies the
unverified.

## Rules

1. Every green check that shells out to another battery runs the child
   with `GOV_SKIP_GREEN=1` in its environment (depth-1: no nested battery
   spawning) and a fresh TMPDIR.
2. The child MUST emit a parseable summary line `N BREAK / M HELD / K ERROR`,
   or -- for unittest-style batteries -- a `Ran N tests` line plus an `OK`
   verdict line with exit 0. Neither = CHECK FAILURE. A non-zero exit WITH
   a parseable summary is evaluated normally (batteries with expected-open
   BREAKs legitimately exit 1); a non-zero exit WITHOUT a summary is a
   CHECK FAILURE.
3. A Python traceback in the child's output means the child raised before
   completing: CHECK FAILURE, even if a summary line is somehow present.
4. Check failures are recorded as ERROR — loud, distinct from HELD. They
   are never reported as "0 BREAKs".
5. `GOV_SKIP_GREEN=1` in the parent's environment skips the check: record
   a skipped note and do NOT spawn the child. A skip is not a pass.
6. The two established check shapes are preserved:
   - exact-summary: the child's pinned verbatim summary line must appear
     in the output; deviation records BREAK.
   - allowlist: BREAK ids the child is allowed to report (expected-open
     findings); any other BREAK id records BREAK.
7. Implementation lives in `evals/green_check.py`. Batteries delegate to
   it instead of reimplementing the subprocess dance. New batteries use
   it from the start.
8. Unittest-suite checks (`python -m unittest <module>`) require exit 0
   and an `OK` verdict line; a missing suite *file* is a CHECK FAILURE
   (ERROR), not a skip. (A missing *module* surfaces as a loud BREAK via
   the child's non-zero exit — also red, never a pass.)
