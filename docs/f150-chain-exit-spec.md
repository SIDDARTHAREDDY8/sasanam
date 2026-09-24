# F150 spec: raise-don't-exit contract for embedder preexec chains

Origin: `evals/FINDINGS.md` → **F150** (LOW, filed 2026-09-24; break
battery `evals/f150chainexit_break.py`: 1 BREAK / 2 HELD / 0 ERROR,
centrally re-verified in normal and `env -u GOV_DEPLOYMENT_MODE`
clean environments). F150 also supersedes F149's documented residual.

## Problem Statement

F149's fix converts a chain entry that *raises* into child exit 98
(`PREEXEC_CHAIN_ABORT_CODE`), and the parent refuses truthfully with
`preexec_chain_failed` and no `egress_wall_launch` event. But the
wrapper's `except Exception → os._exit(98)` cannot intercept a chain
entry that terminates via a direct **`os._exit(N)`** — and
`os._exit(127)` before exec is the sandbox's own documented
fail-closed behavior. A chain entry doing `os._exit(127)` produces a
child that never exec'd (rc 127, sentinel absent) **plus** a false
`egress_wall_launch` event and zero refusals; `run_child()` returns
`CompletedProcess(rc=127)` as if the child executed.

A parent-side check is impossible in general: verified empirically,
`Popen` returns normally when `preexec_fn` calls `os._exit(127)` and
`wait()` reports 127 — indistinguishable from an exec'd child that
exited 127. The conversion must therefore happen child-side, inside
the `_preexec` wrapper, which is the only place that can tell "the
chain aborted" from "the exec'd program exited".

## Solution

Establish a **raise-don't-exit contract** for embedder chain entries,
enforced by the `_preexec` wrapper in the child:

1. New dedicated exception `PreexecChainAbort(exit_code, reason)` in
   `gov/egress_launcher.py`. Chain entries abort by raising it, never
   by calling `os._exit()`.
2. The `_preexec` wrapper converts `PreexecChainAbort` (and, as
   backstop, direct `os._exit()` calls made through the `os` module
   attribute in the chain-running process) into
   `PREEXEC_CHAIN_ABORT_CODE` (98) with a truthful stderr line. The
   parent's existing post-ack grace then refuses with
   `preexec_chain_failed` and emits no launch event — the F149
   machinery, now reachable for the direct-exit path.
3. `gov/sandbox.py`'s own fail-closed `os._exit(127)`s in its chain
   entry raise `PreexecChainAbort(127, <reason>)` instead of exiting.
   Its 5-byte status marker is still written first, so its own
   `_refuse_loud` path (marker/EOF) keeps working in both modes.
4. Sandbox standalone mode (raw `Popen(preexec_fn=...)`, no launcher
   wrapper to convert) translates the raise back to the historical
   `os._exit(127)` at its single call-site boundary, keeping
   standalone behavior bit-identical.
5. Document the residual: chain entries that evade the child-side
   interception (a pre-bound `os._exit` reference, ctypes/raw
   syscalls, restoring `os._exit`, fatal signals) still bypass the
   conversion; the parent cannot distinguish those exits from an
   exec'd child's.

## User Stories

1. As an auditor reading the chained audit log, I want no
   `egress_wall_launch` event for a child that `_exit`'d inside the
   embedder chain without exec'ing, so that every launch event is a
   witnessed fact.
2. As an auditor, I want a chain abort to be refused truthfully as
   `preexec_chain_failed` (never `preexec_recheck_failed`), so the
   refusal names the stage that actually failed.
3. As an embedder author (e.g. sandbox), I want a single documented
   way to abort the child from a chain entry (raise
   `PreexecChainAbort`), so I don't have to guess which exit codes
   the parent can see.
4. As a sandbox operator in standalone mode, I want the fail-closed
   refusal behavior unchanged (loud refusal via the status marker),
   so the launcher integration doesn't change standalone semantics.
5. As a future chain-entry author, I want the interception boundary
   documented (what is converted, what bypasses), so I don't
   accidentally rely on a direct `os._exit()` being visible.

## Implementation Decisions

- **Seam (highest, and only): the `preexec_chain` contract** —
  observable through `FilteredEgressLauncher.launch()` /
  `run_child()` audit events and refusal reasons. No new seams; the
  existing chain-entry tuple is the seam.
- `PreexecChainAbort` lives in `gov/egress_launcher.py` (the contract
  owner); `gov/sandbox.py` imports it (no new cycle: sandbox already
  depends on the launcher).
- The `os._exit` interception is scoped by PID: only calls made in
  the chain-running process itself are converted. Forked descendants
  (notably the sandbox pidns intermediate, which waitpids the worker
  and forwards its status *by design*) keep the real `os._exit`.
  The patch is installed around the chain loop only and restored in
  `finally`; the wrapper's own exits use the saved real reference.
- `except PreexecChainAbort` is ordered before the existing
  `except Exception` in the chain loop; both exit 98, but the
  dedicated path writes the truthful requested-code message.
- Sandbox `_preexec`-level refusals (require_netns / require_pivot /
  require_pidns / fallback-pivot, all in the chain-running process)
  raise explicitly with a reason naming the missing layer. The
  forked worker's and the intermediate's `os._exit` calls are
  untouched (pid guard passes them through; their behavior is
  unchanged).
- Standalone boundary translator lives in `gov/sandbox.py` at its
  single raw-`Popen` call site.
- F149's closure residual text in `evals/FINDINGS.md` is corrected:
  the after-grace failure is effectively unreachable (Popen blocks on
  the preexec error pipe until the chain completes — F150 H3); the
  real residual was the non-98 direct-exit path, now closed by F150,
  leaving only the interception-evading residual above.
- The `launch()` docstring's stale after-grace claim is corrected to
  match.

## Testing Decisions

- A good test here asserts *observable* behavior at the chain seam:
  audit events emitted, refusal raised, reason string, sentinel
  (non-)creation — never wrapper internals.
- Prior art: `tests/test_s7_egress_launcher.py::LauncherUnitTests`
  (F148/F149 regression tests) use the `SimulatedWallFixture` +
  `FilteredEgressLauncher` harness; the F150 tests follow the same
  shape.
- Red-first: the direct-`os._exit(127)` chain tests must FAIL before
  the fix (reproducing the battery's p1 BREAK) and pass after.
- Regression guards: the pid-scoped interception must not break
  forked-descendant `_exit` (chain entry that forks a grandchild
  which `_exit`s keeps working; healthy chain still yields exactly
  one launch event).
- Acceptance: `evals/f150chainexit_break.py` must report
  **0 BREAK / 2 HELD / 0 ERROR** in both normal and
  `env -u GOV_DEPLOYMENT_MODE` clean environments; the full
  canonical suite (`tests/run_tests.py`) must stay OK.

## Out of Scope

- The pidns worker path (a forked grandchild's exit code forwarded
  by the intermediate): unchanged by design; covered by the
  documented residual, not converted.
- `BaseException` (e.g. `SystemExit`, `KeyboardInterrupt`) escaping
  a chain entry: behavior unchanged.
- Moving the F148 ack to post-chain: impossible on pidns paths
  whose intermediate `_exit`s by design; not revisited.
- Any change to the audit event schema or the chained log format.

## Further Notes

- Verified empirically during spec: (a) `Popen` + `preexec_fn`
  doing `os._exit(127)` → parent sees rc 127, no exception (hence no
  parent-side fix possible); (b) `preexec_fn` raising a custom
  exception → parent gets `SubprocessError('Exception occurred in
  preexec_fn.')` (hence the standalone translator, not a bare
  re-raise).
- The 0.5s post-ack grace keeps its purpose: reaping a child that
  died in preexec (errpipe EOF can race the child's actual exit).
  Chain failures are synchronous under Popen, so they always land
  inside the grace; the "fails after the grace" residual was
  unreachable.
