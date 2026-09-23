# F81 Wall-Readiness Ledger (Wave-60, B6 honest readiness)

**Status banner:** F81 stays **LOW OPEN**. This document consolidates
waves 55–59 (+60) into a single readiness record. It does **not** close
F81, does not soften F81's severity, and does not imply the wall
exists. The composed wall (child netns + veth pair + egress proxy +
BPF seccomp filter) has never run as one system anywhere; every
"PROVEN" below is a named, bounded claim with an evidence pointer, and
§3 lists exactly what privileged deployment CI must still prove.

Reading guide: §1 = what is proven and where the proof lives. §2 =
what is specified but unexecuted, with exact run specs. §3 = the
checklist whose completion closes F81. §4 = the per-probe map under
the wave-57 rule (no probe is marked satisfied by a synthetic test
where the design says deployment-only).

## 1. PROVEN (with evidence pointers)

**P1 — Proxy mechanism shape.** `gov/egress_proxy.py` (~700 lines,
stdlib only): CONNECT-tunneling core, first-match-wins ordering
(client check → method check → operator pinholes → static dst-deny
above allow (loopback/RFC1918/link-local/carrier-NAT, never expiring)
→ exact-FQDN allowlist (no suffix wildcards) → deny-all),
per-request hostname resolution through an injected resolver (default
resolver refuses — fail-closed), readiness semantics (not-ready →
503 + `not-ready` verdict; `ReadinessGate` never forks the child),
resolve→connect TOCTOU re-validation (`confirm_connected` checks the
*connected* address). Evidence: `tests/test_egress_proxy.py` — 38
synthetic tests at wave-57 (43 in the current file, +4 F125
regressions), socketpair transport, injected resolvers/connectors,
zero network calls; `workstreams/evals/PROXY_PROTOTYPE_REPORT.md`.
Design: `workstreams/architect/F81_PROXY_EGRESS_DESIGN.md`.
HARD BOUNDARY (stated in module docstring, EmulatedCage, and the
report): this proves the mechanism shape — ordering, resolution
discipline, verdict binding, readiness, honest reporting — NOT the
wall. The no-default-route topology was emulated synthetically
(`EmulatedCage`).

**P2 — BPF program: 166 instructions, byte-proven.** The
filtered-egress cage seccomp filter (`gov/sandbox.py`:
`FILTERED_EGRESS_CAGE_ALLOW` + `_build_seccomp_filter_args`) compiles
to 166 classic-BPF instructions on x86_64 (160 at wave-59; +6 for the
wave-60 F127 ioctl arg-rule block — re-pinned deliberately in
`test_instruction_count_pinned`). Evidence: the pure-Python byte
evaluator (`_bpf_decision`) + `python -m gov.sandbox
--audit-seccomp-cage` (exit 0): every allowlisted name → ALLOW,
socket arg violations (AF_PACKET/SOCK_RAW, NETLINK_ROUTE, SCTP/132,
DCCP/33, SOCK_DGRAM, AF_INET6, bogus) → EPERM, ioctl misuse
(SIOCSIFADDR/SIOCSIFFLAGS/SIOCADDRT, TIOCSTI, TCSETS) → EPERM,
escape/privilege class (unshare/setns/ptrace/bpf/keyctl/mount/
prctl/seccomp/io_uring/…) → KILL, wrong arch → KILL, x32 aliases →
KILL. Tests: `tests/test_sandbox_seccomp_cage.py` (37 tests, 4 live
skipped). Report: `workstreams/evals/SECCOMP_REPORT.md`.
HARD BOUNDARY: verdict semantics proven; kernel load NOT (see D2).

**P3 — netns handshake works-hardened.** `workstreams/architect/
F81_NETNS_HANDSHAKE.md` (attempt log with errno evidence): both
wave-56 untried patterns executed (euid 0). Parent-prepared netns +
setns-join is NOT the pattern (sibling setns → EPERM, even
self-join). Working pattern, proven end-to-end: **child-driven
unshare(CLONE_NEWNET) + parent veth injection** (RTM_NEWLINK succeeds,
RTM_SETLINK netns peer injection succeeds). Child sees only `lo` +
`veth-c`; route table exactly `169.254.240.0/30` (no default route);
direct egress → ENETUNREACH. Break-first battery executed:
setns→host EPERM, userns+setns EACCES, child route-add EPERM, no
netns-fd leakage (CLOEXEC), raw sockets creatable but harmless (own
ns), `ip_forward=0`. Two hardening rules: (1) abstract unix sockets
banned conservatively (cross-netns visibility unprovable —
ECONNREFUSED proves nothing); launcher/proxy MUST never use them;
(2) the proxy-over-veth TCP data leg **cannot be exercised here** —
`connect()` to any veth address returns EPERM even parent-side
(environmental LSM/eBPF veto; iptables wide open) — data leg stays
deployment-verified-only (see D3).

**P4 — Verdict-log tamper-evidence.** Every verdict line carries
`policy_version` + `policy_hash` + `prev_hash` chain;
`verify_file` breaks loudly on byte-flip or line deletion; the log
path is operator-owned absolute, cage-root locations refused at
construction (sep-boundaried prefix check), no env-var override ever
consulted (`EGRESS_VERDICT_LOG` ignored by construction — a cage
child speaking `ALLOW...` down its client socket is just a malformed
CONNECT: denied, logged as deny). Evidence: `TestVerdictLog`
(9 tests) in `tests/test_egress_proxy.py`. Deployment half (hash
rotation observed across live reloads) is D4.

**P5 — Upstream firewall contract.** `docs/UPSTREAM_FIREWALL_CONTRACT.md`
§1: the operator-owned upstream firewall is a required,
out-of-scope layer; its state is a first-class fact — the proxy
reports `firewall_state: absent` honestly rather than assuming it
(`EgressProxy(..., firewall_state=None)` → `"absent"` +
`firewall_state_reason`). Evidence: registry probe
`redteam.f81.proxy_upstream_firewall_absent_reported`. The firewall
itself is operator-owned and deployment-verified-only.

**P6 — CONNECT fuzzing: 9,124 outcomes, F125 closed.** Deterministic
seeded fuzzer (`workstreams/evals/fuzz_connect.py`, seed 20260922):
4,562 authorities × 2 outcomes (parse+decide) = 9,124 outcomes + 610
request-lines through `_parse_authority`/`decide`/`serve_stream`;
properties P1 (never raises) / P2 (never outside grammar) / P3
(accepted targets re-serialize to themselves). Found: 75 distinct
crash inputs pre-fix (`str.isdigit()` accepts non-ASCII digits that
`int()` rejects — F125, LOW availability, fail-closed). Post-fix: 0
crashes, 0 grammar escapes. Evidence:
`workstreams/evals/FUZZ_CONNECT_REPORT.md`; regression tests
`TestF125UnicodeDigitPort` (4 tests). F125 CLOSED.

**P7 — SCTP/DCCP protocol constraint.** Wave-59 break-first catch
(from the CVE-2026-64564/SCTPhantom intake): the wave-58 draft left
`socket()` protocol unconstrained; SCTP-over-SOCK_STREAM (protocol
132) would have passed. Hardened same-wave: protocol ∈ {0,
IPPROTO_TCP} → EPERM otherwise. Evidence:
`test_sctp_protocol_smuggling_dies_with_eperm` + byte audit. No
finding (kernel exploits outside the layer threat model; defense in
depth, not inflation).

**P8 — LOG-tier shake-down (wave-60).** The staging tier did its job:
replaying strace captures of 10 representative workloads through the
exact LOG bytes found the wave-59 blanket ioctl denial SIGSYS-killing
CPython at startup (TCGETS ×493, FIOCLEX ×10 — F127, LOW,
filed+fixed same wave via arg-filtered ioctl, program re-pinned
160→166). Tier-abuse review pinned on the bytes: LOG means
log-and-EXECUTE (permissive, not merely non-enforcing); the errno
tier stays enforced even in staging; no new child-visible oracle from
LOG; no denial→allow laundering (filters immutable; stacking only
restricts further; tier switch is parent-side pre-fork). Evidence:
`workstreams/evals/SECCOMP_LOG_SHAKEDOWN.md`,
`SeccompLogTierAbuseTest` (4 tests), registry probes
`redteam.f81.seccomp_ioctl_arg_filtered` (F127),
`redteam.f81.seccomp_log_tier_abuse_review`.

## 2. DEFERRED TO PRIVILEGED CI (exact specs)

**D1 — Topology: veth pair, child netns, no default route.**
Spec: launcher forks; child `unshare(CLONE_NEWNET)`; parent creates
veth pair (`RTM_NEWLINK`) and injects the peer into the child's netns
(`RTM_SETLINK … netns <child-pid>`); parent assigns
169.254.240.1/30, child 169.254.240.2/30; child route table contains
exactly the /30 link route and NO default route; `lo` up, host
interfaces invisible; direct `connect()` to any non-proxy address →
ENETUNREACH. Must run: the wave-58 break-first battery
(setns→host, userns+setns, child route-add, fd-leakage,
`ip_forward=0`). Blocked here by: `ip netns add` EPERM
(bind-mount) and the environmental connect() veto (P3).

**D2 — Kernel seccomp load.** Spec: run the 4 skipped live tests
(`SeccompCageLiveTest`, `@unittest.skipUnless(seccomp_available())`)
on a kernel where `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER)`
succeeds: install the exact 166-instruction program (KILL tier) in a
pre-exec child and assert (a) a conforming `socket(AF_INET,
SOCK_STREAM)` + `connect` + `send/recv` sequence works,
(b) `socket(AF_PACKET, SOCK_RAW)` → EPERM in the child,
(c) `getsid()` → SIGSYS death with the kill-tier run-note stamp,
(d) the LOG-tier program loads as a default action and logs without
killing (kernel acceptance of SECCOMP_RET_LOG-as-default). Blocked
here by: `PR_SET_SECCOMP` → EINVAL (this environment).

**D3 — Proxy-over-veth data leg.** Spec: with D1 up, bind the real
`gov/egress_proxy.py` to the parent veth address; from the child,
open the client socket the cage profile allows (AF_INET,
SOCK_STREAM), `CONNECT <allowed-host>:443`, assert 200 + upstream
bytes flow and a verdict line on the host log with the live policy
hash; then `CONNECT <denied-host>:443` → deny verdict, no bytes;
then kill the proxy mid-run → child egress fails, run reports
`egress_filtered_unavailable` (never collapsed into
`network_isolated`). Blocked here by: the environmental connect()
veto (P3) — even parent-side connects to veth addresses return
EPERM.

**D4 — Live wall vs the closure-probe family.** Spec: the composed
wall (D1+D2+D3 + operator upstream firewall per P5) runs the §3
checklist probes live. The three wave-57 `proxy_*` probes and the
five wave-25 `egress_*` probes are specified against a real
deployment (`closure-probe:pending` tags); their synthetic passes
prove mechanism, not the wall.

## 3. CLOSURE CRITERIA for F81 (checklist)

F81 closes if and only if ALL of the following hold in privileged
deployment CI. No single layer's synthetic tests satisfy any item
(the wave-57 rule).

- [ ] **C1.** The composed wall — child netns + veth pair (D1) +
      egress proxy (D3) + 166-instruction BPF filter loaded in the
      kernel (D2) + operator-owned upstream firewall (P5) — is
      deployed as one system.
- [ ] **C2.** The wave-25 probe family passes live against the
      composed wall: `redteam.f81.egress_ip_allowlist`,
      `redteam.f81.egress_noproxy_suffix_bypass`,
      `redteam.f81.egress_hosts_repoint`,
      `redteam.f81.egress_resolver_isolation`,
      `redteam.f81.egress_operator_proxy_env`.
- [ ] **C3.** The three wave-57 `redteam.f81.proxy_*` closure-probes
      pass live: `proxy_dst_deny_above_allow`,
      `proxy_crash_fail_closed`, `proxy_verdict_log_policy_hash`.
- [ ] **C4.** The eight wave-59 `redteam.f81.seccomp_*` probes pass
      live (kernel-loaded filter, not just byte evaluation):
      `seccomp_afpacket_raw_smuggling`,
      `seccomp_netlink_route_manipulation`,
      `seccomp_bind_proxy_impersonation`,
      `seccomp_socketcall_multiplexor_absent`,
      `seccomp_deny_by_default_unlisted`,
      `seccomp_unknown_mode_fails_closed`,
      `seccomp_connect_not_filter_confined`,
      `seccomp_sctp_protocol_smuggling`.
- [ ] **C5.** The secret-hygiene residual is explicitly recorded as
      REMAINING OPEN: **split-secret-to-allowed-destination** — a
      secret split across tool calls / connections to an *allowed*
      destination is not reassembled by the proxy (no TLS
      interception, deliberate; wave-55 design verdict stands) and
      stays owned by secret hygiene even after F81 closes. Closure
      of F81 does not claim content inspection.

## 4. Closure-probe map (wave-57 rule applied)

| Probe | Map | Rationale |
|-------|-----|-----------|
| `redteam.f81.egress_ip_allowlist` (w25) | DEFERRED | Needs the live wall (C2). Synthetic pass exists; design says deployment-only. |
| `redteam.f81.egress_noproxy_suffix_bypass` (w25) | DEFERRED | Same — C2. |
| `redteam.f81.egress_hosts_repoint` (w25) | DEFERRED | Same — C2. |
| `redteam.f81.egress_resolver_isolation` (w25) | DEFERRED | Same — C2. |
| `redteam.f81.egress_operator_proxy_env` (w25) | DEFERRED | Same — C2. |
| `redteam.f81.proxy_dst_deny_above_allow` (w57) | DEFERRED | `closure-probe:pending`; needs D3/D4 (C3). |
| `redteam.f81.proxy_crash_fail_closed` (w57) | DEFERRED | Same — C3. |
| `redteam.f81.proxy_verdict_log_policy_hash` (w57) | DEFERRED | Same — C3. |
| `redteam.f81.seccomp_afpacket_raw_smuggling` (w59) | DEFERRED | Byte-verdicts PROVEN (P2) but closure requires the kernel-loaded filter (C4, D2). Per the wave-57 rule, byte evaluation does not satisfy. |
| `redteam.f81.seccomp_netlink_route_manipulation` (w59) | DEFERRED | Same — C4. |
| `redteam.f81.seccomp_bind_proxy_impersonation` (w59) | DEFERRED | Same — C4. |
| `redteam.f81.seccomp_socketcall_multiplexor_absent` (w59) | DEFERRED | Same — C4. |
| `redteam.f81.seccomp_deny_by_default_unlisted` (w59) | DEFERRED | Same — C4. |
| `redteam.f81.seccomp_unknown_mode_fails_closed` (w59) | DEFERRED | Same — C4 (launcher behavior, live). |
| `redteam.f81.seccomp_connect_not_filter_confined` (w59) | DEFERRED | Same — C4. Boundary pinned, live re-confirmation required. |
| `redteam.f81.seccomp_sctp_protocol_smuggling` (w59) | DEFERRED | Same — C4. |

Supporting probes (not closure criteria — NOT-APPLICABLE to the
checklist, listed so nothing is double-counted):

| Probe | Map | Rationale |
|-------|-----|-----------|
| `redteam.f81.proxy_unicode_digit_port_crash` (w58, F125) | NOT-APPLICABLE | Finding F125 CLOSED on synthetic evidence (parser bug, not wall behavior). |
| `redteam.f81.proxy_upstream_firewall_absent_reported` (w58) | NOT-APPLICABLE | Design property (honest reporting), not a wall behavior; deployment-verified. |
| `redteam.f81.seccomp_ioctl_arg_filtered` (w60, F127) | NOT-APPLICABLE | Finding F127 CLOSED on byte evidence; the fixed filter is what C4 loads. |
| `redteam.f81.seccomp_log_tier_abuse_review` (w60) | NOT-APPLICABLE | Staging-tier design review, not a wall behavior. |

**Bottom line:** 8 bounded mechanism claims proven with evidence
pointers (§1); 4 deferred execution specs (§2); a 5-item closure
checklist (§3); 16/16 closure probes honestly DEFERRED, 0 marked
satisfied. The wall does not exist yet. F81 stays LOW OPEN.

## Currency note — wave-78 (2026-09-22)

Wave-78 (supply-chain enforcement: artifact digest-verification gate +
capability leases) touched no egress mechanism. The 8 bounded
mechanism claims (§1), the 4 deferred execution specs (§2), and the
5-item closure checklist (§3) are unchanged; 16/16 closure probes
remain honestly DEFERRED. The composed wall (child netns + veth pair +
egress proxy + BPF seccomp filter) has still never run as one system
anywhere. F81 stays LOW OPEN. Ledger current as of 2026-09-22.
