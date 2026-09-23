# F81 filtered-egress cage: mode-specific seccomp profile DRAFT (wave-58)

Status: **DESIGN + SPEC ONLY — NOT WIRED.** `gov/sandbox.py`'s live paths
are untouched this wave (load-bearing; wave-57 deliberately left them
alone). This is the coordinated-change spec a future wave implements:
the syscall allowlist, the argument-filter rules, the audit story, and
the paper break-first. It follows the repo's existing seccomp idiom
(`DEFAULT_SECCOMP_ALLOW` frozenset + classic-BPF via
`_build_seccomp_filter` + `prctl` install after `NO_NEW_PRIVS`).

## 1. Threat model for this profile

The cage child already sits in a fresh netns with no default route
(wave-58 Lane 1: child-driven unshare + parent veth injection,
break-first-tested). The topology is the wall. This seccomp profile is
**defense in depth with an audit job**: (a) make network misuse fail
loudly and locally at the syscall layer, (b) make namespace/privilege
escalation attempts die unambiguously, (c) deny the child the syscalls
that would let it *observe or influence* anything outside its already-
dead-end netns. It does NOT replace the veth topology, the proxy policy,
or the upstream firewall contract (Lane 3).

Install order (normative): fork → child `unshare(CLONE_NEWNET)` → child
self-configures `lo`/veth (Lane 1 §4) → install this filter →
`exec` workload. The filter therefore never needs to permit the
handshake's own syscalls (`unshare` for net, `RTM_*` netlink).

## 2. Allowlist (repo idiom: frozenset of syscall names)

`FILTERED_EGRESS_CAGE_ALLOW` = `DEFAULT_SECCOMP_ALLOW` with these
**removals** (each removal is a deliberate narrowing for cage mode):

- Network server-side and exotic: `bind`, `listen`, `accept`,
  `accept4`, `shutdown` kept? — `shutdown` kept (clean close);
  remove `bind`, `listen`, `accept`, `accept4` (the child is a pure
  client of the proxy; nothing in its netns should ever listen —
  a listening child socket is either dead code or a rendezvous
  point for a second compromised process).
- Namespace / privilege: `unshare`, `setns` removed (handshake is done
  before install; Lane 1 battery showed escape fails anyway — this
  makes the attempt die at the filter with a clear audit signal).
  `clone`, `clone3`, `vfork` KEPT (threads/subprocesses are legitimate
  workload behavior; namespace-flags inside clone are neutered by the
  absence of `setns` and the EPERM/EACCES reality, documented §5).
- `mount`, `umount2`, `pivot_root`, `chroot` — not in the default
  allowlist; explicitly listed here as MUST-NOT-ADD.
- `ptrace`, `process_vm_readv`, `process_vm_writev`, `bpf`,
  `perf_event_open`, `keyctl`, `add_key`, `request_key` — MUST-NOT-ADD
  (no legitimate cage use; `bpf` in particular must never be available
  to the child).
- `seccomp`, `prctl` — MUST-NOT-ADD: the child must not be able to
  install further filters (which could only tighten, but would muddy
  the audit story) nor read/modify its own dumpable state.
- `ioctl` — removed for cage mode. Nothing legitimate in the
  filtered workload needs it (Python's socket/TCP path does not);
  `ioctl` on net devices is the classic route-manipulation side door.
- `socketcall` (legacy multiplexor) — MUST-NOT-ADD on arches that have
  it; all socket ops go through the individual syscalls below.

**Kept network surface** (client-only, arg-filtered per §3):
`socket`, `connect`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`,
`sendmmsg`, `recvmmsg`, `getsockopt`, `setsockopt`, `getsockname`,
`getpeername`, `shutdown`, `socketpair` (AF_UNIX only — same-process
IPC, harmless).

Everything else in `DEFAULT_SECCOMP_ALLOW` (file IO, mmap/brk,
threads/futex, execve, time, signals, polling) is kept: the child is
supposed to execute code and use files; this profile constrains
*network and privilege*, not computation.

## 3. Argument filters (beyond the current nr-only builder)

The existing `_build_seccomp_filter` matches on syscall number only.
This profile NEEDS argument filtering for `socket(2)`/`connect(2)`; the
coordinated change adds an arg-aware builder (classic BPF reading
`seccomp_data` args at offsets 16/24/32 — scalar values, race-free).

- `socket(domain, type, protocol)`:
  - `domain` MUST be `AF_INET` (2) or `AF_UNIX` (1). All else
    (AF_PACKET, AF_NETLINK, AF_BLUETOOTH, …) → `SECCOMP_RET_ERRNO|EPERM`.
    This is the AF_PACKET-smuggling kill (§5.1) and the
    NETLINK_ROUTE-manipulation kill in one rule.
  - `type` MUST be `SOCK_STREAM` (1) — optionally `SOCK_DGRAM` for
    AF_UNIX only. `SOCK_RAW` → EPERM (raw-socket kill, §5.1).
    `SOCK_NONBLOCK`/`SOCK_CLOEXEC` flag bits are masked out before the
    comparison (they are legitimate).
  - Rationale for allowing AF_UNIX SOCK_STREAM: `socketpair` IPC and
    any pathname unix sockets the workload legitimately uses; abstract
    sockets are banned by launcher policy (Lane 1 §4.3), not by
    seccomp — note the layering.
- `connect(fd, addr, len)`:
  - **Honest correction (design flaw in the earlier draft, fixed
    here):** classic seccomp BPF CANNOT dereference the userspace
    `sockaddr *` at all — it can only inspect the syscall's scalar
    registers (`fd`, `addrlen`). It cannot read the address-family
    byte, let alone compare a `sockaddr_in` against the proxy's veth
    address+port. The earlier draft's "advisory-only due to TOCTOU"
    language was wrong: this is not a race, it is an inability. There
    is NO BPF destination-confinement rule for `connect()` in this
    profile. Destination confinement belongs to the topology (netns:
    no route → `ENETUNREACH` regardless), the proxy's own policy, and
    the upstream firewall — never to seccomp.
  - The scalar `socket(domain, type, protocol)` rule above has no such
    caveat (values, not pointers) and remains the profile's only
    network-shape enforcement.
  - AF_UNIX `connect` to pathname sockets: allowed (workload IPC);
    to abstract sockets: launcher policy bans abstract sockets
    outright (§4.3 of the handshake doc), so the filter need not
    parse `sun_path`.

## 4. Audit story (which denials are logged, which are silent)

Seccomp itself logs nothing unless asked. The story has three tiers:

1. **Loud-local (errno) tier** — `socket`/`connect`/network-misuse
   denials return `EPERM` to the child. The child sees a normal syscall
   failure it can report; the launcher captures the child's stderr/exit
   status. Audit visibility: medium (child-cooperated).
2. **Kill tier** — `unshare`, `setns`, `ptrace`, `bpf`, `keyctl`,
   `mount`, `pivot_root`, `process_vm_*`, `perf_event_open` →
   `SECCOMP_RET_KILL_PROCESS`. These indicate active escape attempts;
   the child dies with `SIGSYS`, which the launcher **must log with
   the syscall number** (via `PTRACE_O_TRACESYSGOOD`? no — simplest
   honest mechanism: the launcher notes `WIFSIGNALED(SIGSYS)` in the
   run record; distinguishing *which* syscall needs either a tracer
   or `SECCOMP_RET_TRAP`). These are never silent: a SIGSYS death is a
   finding-grade event in the run's audit trail.
3. **Staging tier (recommended rollout)** — `SECCOMP_RET_LOG` mode
   (kernel 4.14+) in pre-production: every would-be denial is
   audit-logged without enforcement, so legitimate-workload syscall
   misses are caught before they become production kills. The
   `python -m gov.sandbox --audit-seccomp` flow (needs `strace`)
   remains the source of truth for allowlist maintenance.

What stays **silent by design**: nothing security-relevant. The known
gap is tier-1 denials from a non-cooperating (compromised) child — they
produce no kernel log. That is accepted because tier-1 covers only
network-misuse shapes that the netns already dead-ends; the kill tier
covers the escape shapes, and those are always visible.

## 5. Paper break-first

**5.1 AF_PACKET smuggling.** Child calls
`socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` to sniff/inject at L2,
bypassing the TCP proxy entirely. → Killed at the `socket()` arg
filter: domain ≠ AF_INET/AF_UNIX → EPERM (errno tier). Even unfiltered,
the veth peer in the child's ns sees only its own traffic, but the
filter makes the attempt loud. **Held.**

**5.2 Unix-socket proxy impersonation.** Attacker binds the proxy's
listen path first, then tricks the workload into connecting to the
fake. → The proxy listens on **TCP at the parent-owned veth address**,
not on a filesystem or abstract path. The child cannot bind
`169.254.240.1` (`EADDRNOTAVAIL` — not its address); binding its own
`169.254.240.2:port` impersonates nothing because the workload is
configured (by the launcher, not by child-controlled config) to
connect to the veth address. Filesystem-path sockets in the trust path
are banned; abstract sockets are banned outright (Lane 1 §4.3 —
abstract names are visible across the netns boundary here). **Held by
construction + launcher policy, not by seccomp.**

**5.3 fd-passing a connected socket in (`SCM_RIGHTS`).** Someone hands
the child a connected socket, bypassing `connect()` filtering. →
There is no one to hand it: the child's netns contains only itself;
the parent passes no fds (Lane 1 §4.2 — CLOEXEC + minimal inherit).
`recvmsg`/`sendmsg` stay allowed because the child passing fds to
*itself* is pointless. If the threat model ever gains a multi-process
cage, this rule must be revisited (ancillary-data inspection or
`SECCOMP_RET_ERRNO` on `recvmsg` with `MSG_CMSG_CLOEXEC`… — recorded
as a future-work trigger, not a current hole). **Held by fd hygiene.**

**5.4 `connect()` arg-filter TOCTOU.** Multithreaded child races the
BPF read of the sockaddr against a mutation, connecting somewhere the
filter would have denied. → Acknowledged in §3: the sockaddr rule is
advisory. The backstop is the netns (no route → `ENETUNREACH`, verified
live in Lane 1) and the proxy's policy check on the CONNECT target.
A TOCTOU win buys the attacker a SYN to an address with no route.
**Residual accepted, backstopped.**

**5.5 `clone(CLONE_NEWNET)` / `unshare` re-isolation games.**
Child re-unshares to confuse auditing ("which netns am I in?"). →
`unshare`/`setns` are kill-tier; `clone` with namespace flags would
still be permitted by the nr filter (threads need `clone`) — but a
fresh userns+netns gains the attacker nothing: Lane 1 battery showed
`setns`-back-to-host is EPERM/EACCES even via a fresh userns, and a
deeper-nested netns is *more* isolated, not less. **Held.**

**5.6 Filter-tampering (`prctl`, `seccomp` syscalls).**
Child installs its own filter to mask activity, or queries the filter.
→ Both syscalls are absent from the allowlist (kill tier on attempt).
With `NO_NEW_PRIVS` set before install, the child couldn't escalate
past the filter anyway. **Held.**

**5.7 seccomp-bypass via `io_uring` / `kexec` / modules.**
→ Not in the allowlist (default-deny); `io_uring_setup` never added.
**Held by default-deny.**

## 6. Coordinated-change checklist (for the implementing wave)

1. Add `FILTERED_EGRESS_CAGE_ALLOW` to `gov/sandbox.py` (§2 deltas).
2. Add an arg-aware BPF builder (`_build_seccomp_filter_args`) reusing
   the existing opcode helpers; extend `_bpf_decision` audit helper to
   evaluate arg comparisons (needed for the in-suite audit path).
3. Add a `Sandbox(..., cage_mode="filtered-egress")` switch that
   installs this filter instead of `DEFAULT_SECCOMP_ALLOW`, with the
   proxy veth address+port baked into the `connect()` rule immediates.
4. Launcher work (outside `gov/sandbox.py`): install order per §1,
   SIGSYS logging per §4 tier 2, `SECCOMP_RET_LOG` staging runs.
5. Re-run: canonical suite + `python -m gov.sandbox --audit-seccomp`
   with `strace` after any allowlist change (existing maintenance
   rule, sandbox.py §1).

## 7. Explicitly not done this wave

No `gov/sandbox.py` paths rewired; no filter installed anywhere; no
`_build_seccomp_filter` changes. This draft is airtight on paper for
§5.1–§5.3 and §5.5–§5.7, advisory-only for §5.4 (stated). The
implementing wave must re-run the paper break-first against the real
BPF bytes.
