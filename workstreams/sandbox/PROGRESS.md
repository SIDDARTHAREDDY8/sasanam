# Sandbox workstream — hardened process isolation (2026-09-22)

Owner: Sandbox Engineer (subagent of the engineering lead).
Scope: `gov/sandbox.py` and `tests/test_sandbox_hardened.py` only. Do NOT
touch `gov/log.py`, `gov/executor.py`, `gov/egress_ledger.py`,
`gov/approvals.py`, or `profiles/F-RA2` (concurrent agents). Do not edit
`BUILD_LOG.md`. Do not commit or push.

## What was promoted

`gov/sandbox.py` already had process limits, net/PID namespaces, env
scrubbing, bounded output, timeouts, and the path-authority
`SandboxedToolBackend`. This workstream promoted three more layers:

1. **`pivot_root` filesystem jail** (`use_pivot_root` / `require_pivot_root`)
   - Fresh mount namespace (+ user namespace for unprivileged callers),
     private propagation, bind-mounted staging (`/usr`, `/bin`, `/lib`,
     `/lib64`, `/etc`, `/sbin`), read-only except explicit writable
     mounts, fresh `/proc` bound to the new PID namespace, old root
     detached with `MNT_DETACH` and its mountpoint removed.
   - Pivot-aware backend: the run's sandbox root is bind-mounted at
     `/work` and tool-script paths are translated to it. When combined
     with `drop_privs`, the backend hands the per-run sandbox root to
     `nobody` (parent runs privileged and keeps full access).
2. **UID/GID drop** (`drop_privs` / `require_privdrop`) — `setgroups([])`,
   `setgid`/`setuid` to `nobody` (65534) in the final worker, before exec.
3. **seccomp-bpf** (`use_seccomp` / `require_seccomp`) — classic-BPF
   allowlist (126 syscalls on x86_64), default `KILL_PROCESS`, installed
   after `PR_SET_NO_NEW_PRIVS`, single-threaded in the pre-exec child.

Each layer has a `require_*` fail-closed twin: the child `_exit(127)`s
*before* exec when the layer cannot be established, and `run()` raises
`SandboxError`. Five per-call ground-truth flags (`network_isolated`,
`pid_isolated`, `pivot_active`, `privdropped`, `seccomp_active`) are
reported over a status pipe by the worker itself.

## Env-gated wiring (optional backend, fail-closed)

`install_from_env(executor)` / `sandbox_config_from_env()`:

- `GOV_SANDBOX_BACKEND=1` master switch; anything else leaves the
  executor untouched (`install()` also still works directly).
- `GOV_SANDBOX_PIVOT=1`, `GOV_SANDBOX_PRIVDROP=1`,
  `GOV_SANDBOX_SECCOMP=1` request hardened layers. **A requested layer is
  always required**: a sporadic setup failure raises `SandboxError`,
  never silently downgrades.
- `GOV_SANDBOX_STRICT=1` additionally requires the always-on net and PID
  namespaces.
- If any requested layer is unavailable on this kernel/process,
  configuration raises `SandboxError` instead of installing a degraded
  backend.

## Observed capability behavior (this VM, 2026-09-22)

- Python 3.12.3, x86_64, running as root. `pivot_root`, user/net/PID/mount
  namespaces, `PR_SET_NO_NEW_PRIVS`, and the `nobody` drop all work.
- **seccomp installation is refused** (`EINVAL` even for an allow-all
  filter; `actions_avail` exists but install fails). `seccomp_available()`
  correctly reports False; fail-closed paths raise `SandboxError`; live
  seccomp tests skip; filter *logic* is validated by a pure-Python BPF
  evaluator and by `python -m gov.sandbox --audit-seccomp`.
- The venv interpreter lives under `/home/hatch` (overlay mount,
  `nobody` cannot traverse it): `drop_privs` *without* `pivot_root` needs
  a `nobody`-reachable interpreter or exec fails with 127. The pivot
  staging uses `/usr/bin/python3.12` and is unaffected.
- Mounting `/proc` must happen after `pivot_root` but *before* detaching
  the old root (post-detach mount returns `EPERM` on this kernel).

## Fail-closed behavior (tested)

- `require_pivot_root` / `require_privdrop` / `require_seccomp` with a
  forced setup failure → `SandboxError`, canary file never created.
- Unforced failures report honestly (`pivot_active=False`, note contains
  "fallback"); a regression test pins that `_finish_pivot()` never runs
  when `_do_pivot_root()` never staged (an earlier draft remounted the
  host's `/proc` in that path).
- Env-requested unavailable feature → `SandboxError`, executor untouched.

## Adversarial coverage (tests/test_sandbox_hardened.py, 44 tests)

Pivot: staging-only root, host paths gone, absolute writes blocked,
`..` cannot escape, fresh `/proc` with 1 PID, parent environ unscannable,
staging read-only, fork pressure bounded, network dead. Privdrop: child is
`nobody`, 0600 root file unreadable, parent unsignallable without a PID
namespace, temp jail writable. Seccomp: BPF semantics (126 allow → ALLOW,
22 dangerous incl. `socket`/`ptrace`/`mount`/`bpf`/`unshare` → KILL,
wrong arch → KILL, errno mode → ENOSYS); live tests skip here. Env:
disabled-by-default, unknown values, install wiring, requested ⇒
required, strict ⇒ net/pid required, unavailable ⇒ fail-closed.
Backend-through-pivot: write/read/delete roundtrip as `nobody`,
parent-side escape rejection, quarantine path, `nobody` ownership.

## Honest residuals

- Kernel/VM-grade attacks (kernel exploits, container escapes via kernel
  bugs, side channels, `/proc` info leaks inherent to sharing a kernel)
  are **outside this layer**. For hostile code, **Firecracker** remains
  the documented stronger ops alternative (not implemented here).
- `drop_privs` without `pivot_root` requires a `nobody`-reachable
  interpreter (`sys.executable`); otherwise exec fails closed with 127.
- The seccomp allowlist is a maintenance burden: it was derived from
  `strace` of the real tool workload and must be re-audited whenever the
  workload's syscall footprint changes. Update process:
  `python -m gov.sandbox --audit-seccomp` (builds the filter, checks
  structure + semantics, diffs the workload's syscalls against the
  allowlist). Exit 0 = covered.

## Validation

- `tests.test_sandbox_hardened`: 44 tests — 41 pass, 3 skip (live
  seccomp, kernel refuses install).
- `tests.test_sandbox` (existing): 49/49 pass, no regressions.
- Full suite via `tests/run_tests.py` with a private TMPDIR: see the
  final report for exact counts.
