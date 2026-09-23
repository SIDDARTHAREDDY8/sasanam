# SECCOMP_RET_LOG Staging-Tier Shake-down (Wave-60 Lane 1)

**Question:** does the wave-59 filtered-egress cage seccomp profile kill
legitimate workloads? The classic seccomp failure mode is over-denial —
the filter ships, the workload dies with SIGSYS, and nobody finds out
until production. The LOG staging tier exists to catch exactly this
*before* KILL. This wave shakes it down.

**Method (honest):** live seccomp installation is refused in this
environment (`prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` → EINVAL; see
`workstreams/evals/SECCOMP_REPORT.md` §4), so the LOG tier cannot be
exercised on the kernel here. The shake-down instead replays real
syscall behavior through the exact compiled bytes:

1. 10 representative synthetic workloads run under `strace -f`
   (threads, TCP client→localhost proxy-stand-in, unix socketpair,
   subprocess, ssl import, tempfile/mmap, the repo's standard
   `_AUDIT_WORKLOAD`, plus 3 deliberate probe shapes).
2. Every unique `(syscall, scalar-args)` — 345 shapes — is evaluated
   with `gov.sandbox._bpf_decision` against TWO blobs compiled by the
   same builder: `default_action="log"` (the staging tier) and
   `default_action="kill"` (the production tier).
3. Every non-ALLOW verdict under the LOG blob is a **logged denial**;
   its KILL-blob verdict is the cross-check ("would die under KILL").

Harness retained: `workstreams/evals/log_tier_shakedown.py`
(+ `log_tier_shakedown_inventory.json`, the full 345-shape verdict
table). Re-run after any allowlist or workload change.

## 1. Denial inventory (11 unique shapes, 30 non-ALLOW rows)

| # | syscall | args | LOG-tier | KILL-tier | n | workloads |
|---|---------|------|----------|-----------|---|-----------|
| 1 | ioctl | TCGETS (0x5401) | LOG | KILL | 493 | all 10 |
| 2 | ioctl | FIOCLEX (0x5451) | LOG | KILL | 10 | all 10 |
| 3 | ioctl | TIOCGWINSZ (0x5413) | LOG | KILL | 1 | probe only |
| 4 | socket | AF_INET+SOCK_DGRAM | EPERM | EPERM | 2 | tcp-client, udp-probe |
| 5 | socket | AF_INET6+SOCK_STREAM | EPERM | EPERM | 1 | probe only |
| 6 | socket | AF_INET6+SOCK_DGRAM | EPERM | EPERM | 1 | probe only |
| 7 | socket | AF_NETLINK+SOCK_RAW | EPERM | EPERM | 1 | tcp-client (getaddrinfo) |
| 8 | bind | — | LOG | KILL | 2 | tcp-client (server side) |
| 9 | listen | — | LOG | KILL | 1 | tcp-client (server side) |
| 10 | accept4 | — | LOG | KILL | 1 | tcp-client (server side) |
| 11 | prctl | PR_SET_NAME (15) | LOG | KILL | 1 | probe only |

315/345 shapes ALLOW under both tiers, including the cage→proxy leg
(`socket(AF_INET, SOCK_STREAM|SOCK_CLOEXEC, 0)` → `connect` →
`send/recv` → `shutdown`: ALLOW, ALLOW, ALLOW) and all of CPython's
startup (mmap/mprotect/brk/arch_prctl/rseq/set_robust_list/clone3/
futex/getrandom/epoll/pipe2/eventfd2/statx/newfstatat…).

## 2. Triage

**Shapes 1–2 → F127 FILED and FIXED (applied).** `ioctl(TCGETS)` ×493
and `ioctl(FIOCLEX)` ×10, in *every* workload including bare
`python -I -c "pass"` (18 ioctls before user code runs): CPython's io
stack probes stdio fds for tty-ness at interpreter startup. The
wave-59 blanket ioctl removal ("nothing legitimate needs it") was
wrong — under KILL the first TCGETS SIGSYS-kills the child. Genuine,
independently-reachable over-denial in shipped code → F127 (LOW,
availability). Fix applied (airtight, break-first-clean — §4).

**Shape 3 (TIOCGWINSZ) → HOLD, no change.** Probe-only; no organic
workload used it. Terminal-size probing degrades gracefully
(`shutil.get_terminal_size` falls back to `$COLUMNS`/80×24 on EPERM).
Stays EPERM-by-default; revisit with workload evidence.

**Shapes 4, 7 → HOLD, working as designed (errno tier).** AF_INET
SOCK_DGRAM (shape 4) is glibc `getaddrinfo` trying a UDP path; AF_NETLINK
SOCK_RAW (shape 7) is `getaddrinfo`'s route/address lookup
(`AI_ADDRCONFIG`). Both hit the socket arg rules → EPERM **under both
tiers** — the errno tier is enforced even in LOG staging — and both
workloads *succeeded*: glibc tolerates the EPERM and falls back
(`/etc/hosts`, no route query). This is the errno tier doing its job:
loud-local, fail-soft for legitimate callers, hard for misuse. By
design the cage child does not do its own DNS — resolution belongs to
the proxy — so no allowlist change. Documented, not a finding.

**Shapes 5–6 (AF_INET6) → HOLD, no change.** Probe-only. The proxy is
v4-only by design; an AF_INET6 client socket has no legitimate
destination in the cage topology. If the proxy ever goes dual-stack,
this is a one-line arg-rule delta with the same safety shape as F127.

**Shapes 8–10 (bind/listen/accept4) → HOLD, no change.** These are the
*server side* of the synthetic harness (parent-threaded localhost
stand-in); in the real deployment the proxy listens parent-side and
the cage child is a pure client. A cage child that binds/listens is
outside its role — a listening socket is a rendezvous point for proxy
impersonation (wave-59 §5.2) — so the KILL tier is correct. No change.

**Shape 11 (prctl PR_SET_NAME) → PROPOSE and DEFER (not applied).**
Probe-only: no organic workload called prctl, but real-world agent
libraries *do* name threads (`prctl(PR_SET_NAME)` is what
`pthread_setname_np` becomes; gunicorn/uvicorn-style workers and some
telemetry libs use it). Safety sketch for the deferred fix: arg-rule
`prctl` arg0 ∈ {PR_SET_NAME=15} → ALLOW, else KILL/EPERM — PR_SET_NAME
writes only the calling thread's 16-byte comm name, no privilege, no
cross-thread effect. Why deferred, not applied: (a) prctl is on the
MUST-NOT-ADD list (self-tampering surface: PR_SET_SECCOMP,
PR_SET_NO_NEW_PRIVS, PR_SET_DUMPABLE live in the same syscall — an
arg-rule allow is a bigger design change than the ioctl case, where the
request namespace has no privilege-adjacent members); (b) evidence is
probe-only — no repo workload needs it today. Revisit when a real
workload trips it under LOG staging. Documented as a known
over-denial *risk*, not a finding.

## 3. Tier-abuse review (break-first the machinery itself)

**LOG means log-and-EXECUTE.** The dangerous misunderstanding is that
LOG "doesn't enforce" — precisely, the syscall *runs* after the audit
record. Pinned on the bytes (`SeccompLogTierAbuseTest`): under the LOG
blob, `unshare`/`setns`/`prctl`/`seccomp`/`mount`/`bpf`/`keyctl`/
`ptrace` all → LOG (execute); under KILL → KILL. The staging tier is
*permissive*; the wall in staging is the errno tier + netns + rlimits
+ privdrop, not seccomp default-deny.

**The errno tier is enforced even in staging.** Socket/ioctl arg
violations → EPERM under BOTH blobs (verified). Staging is never
"everything allowed": network-misuse shapes stay blocked.

**No new child-visible oracle from LOG.** EPERM is identical across
tiers, so LOG hands the cage no new oracle for the arg rules.
Survival-probing can distinguish allowlisted vs defaulted syscalls
under LOG — but the allowlist ships in `gov/sandbox.py` source; it is
not a secret, so no exfiltration channel is created. The kernel audit
log itself is host-side; the child cannot read it. (The LOG tier's
oracle purpose — mapping the filter — is aimed at the *operator*
reading host audit logs in staging, which is legitimate and intended.)

**No denial→allow laundering.** Filter bytes are immutable
post-install; `prctl`/`seccomp` are KILL-tier, so under KILL the child
cannot install/replace a filter (SIGSYS). Under LOG, `prctl(
PR_SET_SECCOMP)` would execute — the child *can* stack an additional
filter — but stacking can only further restrict: the kernel takes the
numerically-smallest action across stacked filters
(KILL_PROCESS < … < LOG < ALLOW), so a permissive child filter never
overrides the base filter's LOG/KILL/EPERM, and existing filters
cannot be removed. The tier switch itself is parent-side
(`GOV_SANDBOX_SECCOMP_LOG` read pre-fork in `_make_preexec`); the
child cannot downgrade its own run.

**Operator hazard (open question for wave-61):** `GOV_SANDBOX_SECCOMP_LOG=1`
in production silently dissolves default-deny into log-and-execute.
Current control is the run-note stamp ("seccomp LOG staging mode:
denials were audit-logged, NOT enforced"), which is audit, not
prevention. Proposed: a hard production guard (launcher refuses LOG
tier when a production flag is set). Deferred — new env-var surface,
needs design, not an airtight one-liner.

**Kernel acceptance of LOG-as-default is deployment-proven only.**
`SECCOMP_RET_LOG` exists precisely for allowlist shakedown and is
valid as a default action, but this environment refuses
`PR_SET_SECCOMP` entirely (EINVAL), so kernel acceptance of the
program *as a whole* remains gated on the 4 skipped live tests in
privileged CI. The byte evaluator proves verdict semantics, not
kernel load.

## 4. Applied delta — F127 (airtight, break-first-clean)

`_CAGE_IOCTL_ARG_RULES`: `ioctl` arg1 (request) ∈ {TCGETS 0x5401,
FIOCLEX 0x5451} → ALLOW; else → SECCOMP_RET_ERRNO|EPERM. Same
`_build_seccomp_filter_args` machinery as the socket rules; forward
jumps only; program re-pinned 160 → 166 instructions
(`--audit-seccomp-cage` green).

Safety argument (break-first): TCGETS is a pure read of termios into
a userspace buffer — no device state change, no information the fd
doesn't already expose via read(). FIOCLEX sets FD_CLOEXEC — strictly
reduces fd survivability across exec. Neither is privilege-shaped.
The attack shapes the wave-59 removal targeted all die at the EPERM
tier: SIOCSIFADDR/SIOCSIFFLAGS/SIOCADDRT (route manipulation),
TIOCSTI (input injection), TCSETS*/TCSETSW (terminal reprogramming) —
asserted in `test_ioctl_misuse_requests_die_with_eperm`. High-bit
request smuggling: filter sees low 32 bits, kernel validates full
64 bits (unknown → ENOTTY) — can only err toward denial, pinned in
`test_ioctl_high_bit_request_truncation_pinned`. Legitimate behavior
is unbroken: the 503-shape workload corpus now evaluates ALLOW for
TCGETS/FIOCLEX under both tiers.

No other allowlist deltas applied. The full denial inventory above is
the proposed-delta list; everything not in §4 is HOLD or DEFER with
the reason stated.

## 5. Honest limits

- No kernel was involved: verdicts are from the pure-Python byte
  evaluator on the exact compiled bytes. Timing/race behavior under a
  real LOG filter (audit-log volume, log ordering vs execution) is
  not covered.
- strace captures are from CPython 3.x on this image's glibc; a new
  Python minor, musl, or a different libc can add syscalls — the
  documented update process (`--audit-seccomp` + this harness) is the
  control, and the symptom of a miss stays loud (SIGSYS), never
  silent.
- The 3 probe shapes are synthetic; organic coverage is 7 workloads.
  The realistic battery (Lane 3) runs separately and does not install
  seccomp here (honest fallback, `seccomp_active=False`).

---

## 6. Wave-61: LOG-tier production guard — design (Lane 1)

**Problem restated.** Today the only control between a production run
and `GOV_SANDBOX_SECCOMP_LOG=1` dissolving KILL default-deny into
log-and-execute is a run-note stamp (§3 "Operator hazard"). The stamp
is audit, not prevention. The seam is exactly the fail-open class
this project exists to kill: a single env var silently downgrades the
strongest layer. (Severity of the *seam*: the downgrade is loud-local
only if someone reads the note; nothing stops the launch.)

**Threat model, stated honestly.** The guard's adversary is **operator
misconfiguration**, not a malicious environment writer: a stray
staging env var in a production launcher (copied unit files, debug
leftovers, CI bleed-through). Anyone who can write the launcher's
environment can already unset `GOV_SANDBOX_BACKEND` (sandbox off
entirely) or bypass the launcher — env-writer resistance is out of
scope and is documented as a boundary note, never a finding. The
guard converts a *silent* misconfiguration into a *loud refusal*.

### (a) Who is authoritative for tier selection

Precedence, highest first:

1. **Explicit constructor kwarg** — `Sandbox(...,
   deployment_mode="staging")`. Operator code: the most deliberate
   channel, wins over everything.
2. **`GOV_SANDBOX_DEPLOYMENT_MODE` env** — operator-explicit launcher
   signal, mapped by `sandbox_config_from_env()`. Convenience only.
3. **Default: `production`.**

`GOV_SANDBOX_SECCOMP_LOG=1` is demoted from authority to *request*:
it is honored **only** when deployment_mode == "staging". In any
other state it is either ignored (garbage values — `_env_flag` is
already strict `== "1"`) or refused loudly (production + LOG →
`SandboxError`, no launch).

### (b) What "production" means here

There is no deployment-mode flag in this codebase today (checked:
`production` appears in `gov/` only in unrelated contexts —
credential shapes, approval docs). The least-privilege definition is:

- `deployment_mode ∈ {"production", "staging"}`, new `Sandbox`
  kwarg, default **`"production"`**. Unknown values → `ValueError`
  at construction (fail-fast; an unknown mode never silently means
  "no guard").
- `GOV_SANDBOX_DEPLOYMENT_MODE` env maps into the same kwarg via
  `sandbox_config_from_env()`; garbage/empty → default production.
- "Production" therefore means: *the operator did not explicitly
  declare staging*. Least privilege: ambiguity defaults to KILL.

In staging, the default tier is still KILL — LOG requires the
explicit `GOV_SANDBOX_SECCOMP_LOG=1` request. No downgrade by
default, even in staging.

### (c) Fail-closed direction for every ambiguous state

| deployment_mode | LOG requested? | verdict |
|---|---|---|
| production (incl. default) | yes | **REFUSE TO LAUNCH, loudly** — `SandboxError` naming the env var, raised before jail creation. Not "force KILL and continue": a contradiction between deployment mode and tier is misconfiguration; launching in either mode assumes intent we cannot know, and force-KILL normalizes the misconfiguration (the stray var persists; the audit note is the only trace — the current stamp's failure mode, moved not fixed). |
| production | no | KILL (unchanged behavior) |
| staging | yes | LOG allowed; run note stamped (existing stamp retained) |
| staging | no | KILL (no downgrade by default) |
| unknown mode | — | refuse at construction (`ValueError`); guard never sees it |
| guard itself raises | — | no cage launch; exceptions propagate, nothing caught |

The guard is a **single chokepoint at the top of `run()`**, before
jail creation. Tier is resolved exactly once per run and flows as a
*value* into `_make_preexec(seccomp_tier=...)`; the run note uses the
same resolved value. This kills the current double-read (line 1695
note re-read vs line 1801 preexec read): after this change there is
no second read to go stale, and no TOCTOU between decision and
install — the child-side `_preexec` never touches the environment
for the tier.

Auditing the refusal: `SandboxError` carries the exact var name and
the contradiction (`deployment_mode='production'`). The codebase's
refusal convention is raise-loudly (cf. unknown `cage_mode`,
canary-plant failure); there is no audit-log parameter on `Sandbox`
to thread, so the exception *is* the loud record, and no result is
ever returned for a refused run.

### (d) How the guard is tested (trust-path discipline)

The BPF analog of byte-pinning for a config guard is the **exhaustive
decision table**: `_resolve_seccomp_tier(deployment_mode,
log_requested)` is pure and every `(mode, request)` pair is pinned in
`SeccompLogGuardTest`, plus structural pins:

- production+LOG → `SandboxError`, raised before `Popen` (no child
  spawned — patched `Popen` would trip an assertion);
- staging+LOG → allowed, note stamped; staging alone → KILL;
- `_env_flag` strictness pinned for empty/garbage/unicode LOG values
  (only exact `"1"` — after strip — requests LOG);
- unknown deployment mode → `ValueError` (constructor + resolver);
- kwarg beats env (`sandbox_config_from_env` mapping pinned);
- **exactly-one-read**: a counting wrapper around `_env_flag`
  asserts the tier var is read once per `run()` — decision and note
  share the resolved value, no second read, no decision/install
  TOCTOU;
- **no downgrade laundering**: KILL-tier install raising `OSError`
  never retries with `default_action="log"` (call recorder on the
  installer; all calls carry `"kill"`);
- child-side isolation: `GOV_SANDBOX_SECCOMP_LOG` is not in
  `DEFAULT_ALLOWED_ENV` — the cage child cannot see, let alone flip,
  the tier var (tier decision is parent-side pre-fork regardless).

Registry: `redteam.f81.seccomp_log_guard_*` probes delegating to the
guard tests (expected: denied — the attack shapes are refused).

**Deliberately not in this design:** a config-file authority (no
config-file machinery exists for the sandbox; inventing one is new
surface), build-time constants (kills the legitimate staging use),
and force-KILL-and-continue (argued above — refusal is the honest
fail-closed).
