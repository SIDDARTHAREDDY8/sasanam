# Wave-59 SECCOMP report: filtered-egress cage profile — implementation + break-first

Date: 2026-09-22. Wave theme: seccomp implementation (real BPF bytes +
break-first re-run). Implements the wave-58 design-only draft
`workstreams/architect/F81_SECCOMP_PROFILE_DRAFT.md` §§2–4 as shipped
code in `gov/sandbox.py`. This wave is the explicit handoff target:
"implementing wave re-runs break-first against real BPF bytes."

## 1. What was implemented (Lane 1)

All in `gov/sandbox.py`, following the repo's existing seccomp idiom
(`DEFAULT_SECCOMP_ALLOW` frozenset + classic-BPF builders + `prctl`
install after `NO_NEW_PRIVS`) — no parallel mechanism, no fork of the
STRICT path:

- **`FILTERED_EGRESS_CAGE_ALLOW`**: `DEFAULT_SECCOMP_ALLOW` minus
  `ioctl` (net-device route-manipulation side door), minus the defensive
  removals `bind`/`listen`/`accept`/`accept4`/`unshare`/`setns` (absent
  from DEFAULT today; listed so a future DEFAULT addition cannot
  silently widen the cage), plus the client-socket family: `socket`,
  `connect`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `sendmmsg`,
  `recvmmsg`, `getsockopt`, `setsockopt`, `getsockname`, `getpeername`,
  `shutdown`, `socketpair`. `clone`/`clone3`/`vfork` kept (threads are
  legitimate; namespace flags inside clone are neutered by the
  setns/unshare kill tier).
- **`_build_seccomp_filter_args`**: arg-aware classic-BPF builder reusing
  the existing opcode vocabulary (`LD_W_ABS`, `JEQ_K`, `RET_K` only —
  the `_bpf_decision` audit evaluator needed arg support, not new
  opcodes). Labels assembled by `_bpf_assemble`; **all jumps forward**,
  verified by a test that walks every instruction. Layout: 4-insn arch
  header, nr scan (arg-ruled numbers route to per-syscall check blocks),
  default action, ALLOW, then the arg-check blocks each ending in a
  local RET_ALLOW.
- **`_CAGE_SOCKET_ARG_RULES`** on `socket(domain, type, protocol)` —
  scalar args only (seccomp_data offsets 16/24/32, low 32 bits):
  domain ∈ {AF_UNIX=1, AF_INET=2}; type = SOCK_STREAM modulo
  SOCK_NONBLOCK|SOCK_CLOEXEC (4 precomputed immediates, no ALU opcode);
  protocol ∈ {0, IPPROTO_TCP}. Violations → `SECCOMP_RET_ERRNO|EPERM`.
  Compiled program: **160 instructions** on x86_64 (pinned in tests as a
  tripwire).
- **Mode selection**: `Sandbox(..., cage_mode="filtered-egress")`
  installs the cage filter instead of `DEFAULT_SECCOMP_ALLOW` — it
  composes with the existing STRICT machinery (same `_harden_worker`,
  same status-pipe ground truth, same `require_seccomp` fail-closed
  semantics), it does not fork it. Misconfiguration fails closed:
  unknown mode → `ValueError` at construction; `cage_mode=
  "filtered-egress"` without `use_seccomp=True` → `ValueError`;
  `GOV_SANDBOX_CAGE_MODE=<unknown>` → `SandboxError` from
  `sandbox_config_from_env`; cage mode without `GOV_SANDBOX_SECCOMP=1`
  → `SandboxError`. Never "no cage".
- **Audit story** (draft §4, implemented): tier 1 (errno) — socket arg
  violations return EPERM to the child, loud-local; tier 2 (kill) —
  unlisted syscalls die with SIGSYS and `_supervise` now stamps
  "seccomp kill-tier denial" on the run note (finding-grade, never
  silent); tier 3 (staging) — `default_action="log"` /
  `GOV_SANDBOX_SECCOMP_LOG=1` selects `SECCOMP_RET_LOG` (kernel 4.14+),
  denials audit-logged without enforcement, stamped on the run note so a
  staging run can never be mistaken for an enforced one.
- **Audit CLI**: `python -m gov.sandbox --audit-seccomp-cage` — byte-level
  audit of the cage profile (structure, 139 allowlisted, default KILL,
  full arg semantics, high-bit truncation pin, deliberate connect-ALLOW,
  x32-alias, wrong-arch). Exit 0 = holds. The existing
  `--audit-seccomp` (DEFAULT profile) is untouched and still green.

## 2. Break-first re-run against the real BPF bytes (Lane 2)

`tests/test_sandbox_seccomp_cage.py` (30 tests; 26 pass + 4 live
skipped, see §4). Every attack evaluates the exact compiled bytes via
`_bpf_decision` — the tests attack the filter, not the draft:

| # | Attack | Verdict on bytes |
|---|--------|------------------|
| 5.1 | `socket(AF_PACKET, SOCK_RAW, …)` L2 sniff/inject | **Held** — EPERM at the domain arg check |
| 5.1b | `socket(AF_INET, SOCK_RAW, 6)`, `SOCK_DGRAM`, `AF_INET6` | **Held** — EPERM |
| 5.1c | SCTP-over-STREAM (`AF_INET, SOCK_STREAM, 132`) — draft left protocol unconstrained | **Held** — EPERM at the new protocol check (break-first catch, §3) |
| 5.1d | `AF_NETLINK, SOCK_RAW, NETLINK_ROUTE` route manipulation | **Held** — EPERM |
| 5.2 | Proxy impersonation: bind the proxy's socket path first | **Held** — `bind`/`listen`/`accept`/`accept4` are KILL tier; nothing in the cage can listen, so there is no rendezvous point. (Proxy listens on TCP at the parent-owned veth address — held by construction + launcher policy; the filter removes the capability entirely.) |
| 5.3 | fd-passing (`SCM_RIGHTS`) a connected socket in | **Boundary, documented** — `recvmsg`/`sendmsg` stay nr-ALLOW (pinned). The control is fd hygiene (CLOEXEC + minimal inherit; parent passes no fds — wave-58 Lane 1 §4.2), not the filter. The threat model honestly bounds this: fd-passing crosses the trust boundary the cage defines. A multi-process cage would need ancillary-data inspection (recorded trigger). |
| 5.4 | `connect()` destination confinement | **Honest non-goal, pinned** — the filter returns ALLOW for `connect` deliberately: classic BPF *cannot* dereference the `sockaddr *` (inability, not TOCTOU — draft §3 correction stands). Confinement is the netns's job (no route → ENETUNREACH), the proxy's policy, the upstream firewall. A test pins the ALLOW so a future "clever" connect rule is recognized as theater. |
| 5.5 | `clone(CLONE_NEWNET)` / `unshare` re-isolation | **Held** — `unshare`/`setns` KILL tier; `clone` stays ALLOW for threads (neutered: no setns to rejoin anything). |
| 5.6 | `prctl`/`seccomp` filter tampering | **Held** — both absent from the allowlist → KILL tier; NO_NEW_PRIVS set before install regardless. |
| 5.7 | `socketcall` multiplexing; x32 aliasing | **Held** — x86_64 has no `socketcall` number; `nr\|0x40000000` never matches the scan → KILL. |
| D | Deny-by-default: unlisted syscall (`getsid`) | **Held** — KILL, not ALLOW. |
| M | Unknown `cage_mode` / cage-without-seccomp | **Held** — loud refusal (`ValueError` / `SandboxError`), never silent "no cage". |

**Disposition: no finding filed.** Every break shape holds at the bytes;
the two non-holds are documented boundaries (5.3, 5.4), not misses. Next
free finding number stays **F127**.

## 3. The SCTP break-first catch (same-wave hardening, no finding)

During Lane 3 intake this wave surfaced **CVE-2026-64564 ("SCTPhantom",
SCTP UAF → container escape, 6/8 attempts with the *default* seccomp
profile active)**. The researchers' exposure factors explicitly include
"access to raw and packet sockets" and "the seccomp configuration". The
draft's `socket()` rules constrained domain and type but left protocol
unconstrained — `socket(AF_INET, SOCK_STREAM, 132)` (SCTP) would have
passed the filter. Kernel exploits are *outside* this layer's threat
model (documented honest residual: the sandbox assumes a trusted
kernel), so this is defense-in-depth tightening, not a control bypass —
**hardened same-wave, no F-number consumed** (filing would be finding
inflation). The protocol arg rule ({0, IPPROTO_TCP}) costs nothing
legitimate (the proxy is TCP-only; AF_UNIX ignores protocol) and also
denies DCCP (33) and any future protocol smuggling through SOCK_STREAM.
`CVE-2026-31431` ("Copy Fail", AF_ALG page-cache write; mitigation:
"drop a custom seccomp profile blocking AF_ALG") is likewise denied at
our domain allowlist (AF_ALG=38 ∉ {1,2}) — noted as defense-in-depth
validation, no action. `CVE-2026-92574` (CRI-O checkpoint restore
retaining seccomp/no_new_privs state) is a deployment-hygiene boundary
note: our filter installs fresh per child, never inherited — no CRI-O in
this deployment.

## 4. Exercised vs emulated — errno evidence (no faked passes)

- `PR_SET_NO_NEW_PRIVS` in a forked child: **returns 0** (succeeds).
- `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)` in a forked child:
  **fails with errno 22 (EINVAL)** — the kernel/container policy refuses
  filter installation in this environment. `seccomp_available()` →
  `False`, honestly.
- Therefore **no live filter test runs here**: the 4 live tests
  (`SeccompCageLiveTest`: errno-tier EPERM-not-death, kill-tier SIGSYS,
  end-to-end cage mode, SIGSYS run-note stamping) skip via the same
  `@unittest.skipUnless(SECCOMP, …)` convention as the existing
  `SeccompLiveTest`. They are written, reviewed, and queued for a
  privileged CI — they are not marked passing.
- What **is** proven here: the exact compiled bytes (160 insns) evaluated
  by `_bpf_decision` — the same evaluator the repo's existing seccomp
  audit uses — covering every allowlisted name, every misuse shape, the
  kill tier, the arch check, the x32 alias, the high-bit truncation pin,
  and the LOG staging encoding. `python -m gov.sandbox
  --audit-seccomp-cage` exits 0.
- The install *path* (`_install_cage_seccomp_filter` → prctl) is
  exercised up to the honest refusal; the refusal itself is the
  fail-closed behavior (`require_seccomp` → child `_exit(127)` before
  exec, `SandboxError` from the env wiring — both covered by tests that
  force the failure).

## 5. What was deliberately not done

- **No `connect()` destination rule.** Impossible in classic BPF
  (sockaddr is a userspace pointer); the draft's honest correction
  stands and is pinned by test. Anyone proposing one later is proposing
  theater.
- **No end-to-end filtered-egress cage in `Sandbox.run`.** The mode
  switch installs the *seccomp profile*; the full cage (netns + veth +
  proxy + this filter, proxy-over-veth data leg) remains
  deployment-verified-only per wave-58 (EPERM on veth-address connects
  even parent-side in this environment). **F81 stays LOW OPEN** — its
  closure criteria (wave-57/58: a real wall + the wave-25/wave-57 probe
  family passing in a privileged deployment CI) are not met by a
  seccomp profile alone, however well break-tested.
- **No `seccomp()`-syscall-based install path** (the `prctl` idiom is the
  repo's; kept).
- **No change to `DEFAULT_SECCOMP_ALLOW` or `_build_seccomp_filter`**
  (beyond the additive `"log"` default-action branch): the STRICT path
  compiles byte-identical filters to before this wave.

## 6. Open questions for Wave-60

1. Privileged-CI run of the 4 skipped live tests (and the pre-existing
   `SeccompLiveTest`) — the bytes are proven; the load path is not.
2. The remaining F81 closure work is the composed wall (netns + veth +
   proxy + this filter) with the wave-25 `redteam.f81.*` hostname-trust
   family and the wave-57 proxy probes passing against the real
   topology — a deployment-CI wave, not a bytes wave.
3. `SECCOMP_RET_LOG` staging runs against a real workload to shake
   down the cage allowlist before any production use.
4. Revisit 5.3 if the threat model ever gains a multi-process cage
   (ancillary-data inspection on `recvmsg`).
5. Upstream kernel patch status for CVE-2026-64564 / CVE-2026-31431 in
   the deployment base image (defense-in-depth; the filter is not the
   patch).

## 7. Provenance

- Draft: `workstreams/architect/F81_SECCOMP_PROFILE_DRAFT.md` (wave-58).
- Intake: `research/intake-wave59-2026-09-22.md` (this wave).
- Tests: `tests/test_sandbox_seccomp_cage.py` (30 tests).
- Registry: `redteam.f81.seccomp_*` × 8 in `evals/scenarios/registry.yaml`
  (finding: F81, closure: n-a; the connect-boundary probe is expected:
  flagged).
- Audit: `python -m gov.sandbox --audit-seccomp-cage` (exit 0).
