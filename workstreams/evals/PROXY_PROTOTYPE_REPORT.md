# F81 Proxy Prototype Report — Wave-57 (2026-09-22)

**Status: MECHANISM-SHAPE PROTOTYPE. F81 stays LOW OPEN. This report, the
code, and the green tests do not close F81 and are not a step toward
closure on their own — closure needs the real wall plus deployment
verification (criteria restated in §7).**

## 1. What was built

- `gov/egress_proxy.py` (~700 lines, stdlib only): the CONNECT-tunneling
  egress proxy core from the wave-56 design doc
  (`workstreams/architect/F81_PROXY_EGRESS_DESIGN.md`), code parts of the
  ADR shape.
- `tests/test_egress_proxy.py`: 38 tests, all synthetic (socketpair
  transport, injected resolvers/connectors — zero network calls).
- Three probes registered in `evals/scenarios/registry.yaml`:
  `redteam.f81.proxy_dst_deny_above_allow`,
  `redteam.f81.proxy_crash_fail_closed`,
  `redteam.f81.proxy_verdict_log_policy_hash` (closure-probe:pending,
  wave-25 pattern — registered, not gate-executed).

## 2. Squid-vs-bespoke decision: BESPOKE

Decided on the auditability bar ("every verdict auditable, no opaque
binary behavior in the trust path"):

1. **Auditability.** The entire trust path — CONNECT parse → rule order →
   dst-deny → verdict — is ~500 lines of stdlib Python, readable end to
   end in one sitting. Squid is ~1M LOC of C plus an ACL/cache/TLS-bump
   config language: opaque surface in the trust path.
2. **Dead surface.** Squid's caching, TLS-bump, and helper processes are
   dead config for our CONNECT-only shape but remain reachable attack
   surface and a CVE stream to track. The bespoke core has no caching, no
   TLS interception (deliberate), no helpers.
3. **Supply chain.** Bespoke = zero dependencies (stdlib only). Squid =
   a packaged binary with its own vulnerability history inside the
   trust-root-adjacent component.
4. **The ADR chose squid for enterprise recognizability; our bar is
   explicitly different** (auditability over recognizability). Recorded
   as a deliberate divergence, not an oversight.

**Honest cost admitted:** bespoke userspace is our own bug surface.
Mitigations: radical minimalism (CONNECT only, strict config-as-data),
the module's self-guarantees (`PROXY_SELF_GUARANTEES`: one validated
input; connector called only on allow with the decided target;
connect-time re-validation; no privileged operations in the module;
malformed policy/version skew → no-network), and the design doc's §6.4
requirement — an operator-owned upstream firewall layer at deployment —
which the bespoke choice does NOT remove. A deployment without that
layer has not implemented the design.

## 3. Mechanism-shape proof (what the 38 tests demonstrate)

| Mechanism | Proof |
|---|---|
| Rule ordering (dst-deny above allow) | `TestOrdering`: allowed name → 10.x/172.16.x/192.168.x/127.x/169.254.x/100.64.x/::1/fc00::/fe80::/mapped-loopback all denied by `dst-deny`; never reach the allowlist |
| Operator pinhole above dst-deny | Explicit exemption visible in rule order; non-pinhole names still denied |
| No suffix trust (Wiki shape) | `api.example.com` allowed; `sub.api.example.com`, `notapi.example.com`, `api.example.com.evil.com` denied; `*.example.com` in policy refused at parse |
| Per-request resolution, no pinning | Resolver consulted once per CONNECT (call-count assertion) |
| Raw-IP authorities never allowlistable | `CONNECT 93.184.216.34:443` denied without consulting the resolver |
| Readiness: not-ready = no network | 503 + `not-ready` verdict; `ReadinessGate.launch` raises without forking the child |
| Resolve→connect TOCTOU | `confirm_connected` re-validates the *connected* answer: rebind to 127.0.0.1 → `dst-deny-toctou`, no bytes flow; public→public rebind stays allow (documented as policy, not breach) |
| Verdict log outside the cage | Cage-root paths refused at construction; relative paths refused; sep-boundaried prefix check; no env-var override consulted |
| Verdicts hash-bound to policy | Every line carries `policy_version` + `policy_hash` + `prev_hash` chain; rotation changes the hash on subsequent lines; byte-flip and line-deletion both break `verify_file` loudly |
| Policy-as-data confusion | Unknown keys, suffix wildcards, IP-literal allow entries, wildcard binds, malformed reloads all refused loudly; malformed reload keeps the old policy serving; version skew → `PolicyVersionMismatch`, no 200 ever |
| Crash fail-closed (emulated) | Killed proxy → client sees EOF; direct attempts raise `NoRouteError`; status reports `egress_filtered_unavailable=True`, `network_isolated=False` (never collapsed) |
| Cage cannot forge verdicts | `ALLOW ...` down the client socket is just a malformed CONNECT — denied, logged as deny |
| Tunnel shape | 200 then opaque bidirectional byte relay over socketpair (no content inspection — deliberate) |

## 4. The EPERM boundary (what is NOT proven)

Real network namespaces cannot be exercised in this environment
(`unshare(CLONE_NEWNET)` / `setns()` → EPERM). Consequences, stated
plainly:

- The **topology half** of the design (veth pair, child netns with no
  default route, proxy outside the child's netns) is
  **deployment-verified-only**. `EmulatedCage` is a model: its
  `NoRouteError` is raised by Python, not by the kernel.
- The prototype proves the **mechanism shape**: ordering, resolution
  discipline, verdict binding, readiness semantics, honest reporting.
- The five wave-56 prototype blockers stand: (1) parent↔child netns
  handshake in an EPERM environment — untried patterns remain untried;
  (2) coordinated seccomp redesign (socket family currently denied
  wholesale); (3) proxy implementation choice — now decided (bespoke,
  §2); (4) per-deployment upstream firewall spec; (5) probe
  implementation against a real deployment — registered this wave,
  pending.
- **Under no circumstances does this wave close F81.** The prototype's
  green tests imply the mechanism is shaped right; they imply nothing
  about the wall existing.

## 5. Break-first accounting (wave-56 five-part residuals)

1. **Readiness race** → closed in the mechanism: `ready` flag + 503,
   plus `ReadinessGate` refusing to fork. The topological answer (no
   route to race) remains deployment-only.
2. **DNS-rebind inside TTL windows** → narrowed as designed: static
   dst-deny re-validated against the connected answer closes the
   private-space direction regardless of TTL; the residual (public→
   public flip) is pinned by test as policy-not-breach.
3. **Verdict-log tampering from the cage side** → construction refusal
   of cage paths, no env override, tamper-evident chain. Residual
   stands as designed: a fully compromised proxy writes false verdicts,
   but false verdicts do not create routes (evidence-grade, not
   control-grade).
4. **Proxy compromise containment** → the module's self-guarantees are
   tested (connector never called on deny; called only with the decided
   target; no privileged operations exist in the module). The
   operator-owned upstream firewall remains required and out of scope —
   the proxy alone does NOT bound a compromised proxy's upstream reach;
   it only guarantees it cannot be tricked into connecting somewhere it
   did not decide to connect to.
5. **Policy-as-data confusion** → refused loudly (unknown keys, Wiki
   wildcards, IP pins, wildcard binds); malformed reload keeps old
   policy; version skew → no-network. All tested.

No new findings. The break-first pass surfaced no independently-
reachable miss: every residual above was either closed in the mechanism
or is a documented deployment-owned boundary, not a finding. F81 stays
LOW OPEN; next free finding number F125.

## 6. What was deliberately not done (and why)

- **No real netns/veth wiring.** EPERM environment; attempting it would
  produce a fake wall. The honest move is the emulated model + the
  stated boundary.
- **No TLS interception / content inspection.** Deliberate per the
  design (destinations, never payloads). The split-secret-to-allowed-
  destination residual stays owned by secret hygiene (design §7.3).
- **No tool-call reassembler.** Wave-55 verdict stands.
- **No changes to `gov/sandbox.py`, the seccomp profile, or the canary
  program.** The prototype is additive; the strict deny-all mode is
  untouched.
- **No wiring of the proxy into the sandbox launcher.** That is a
  deployment-integration wave, gated on the netns handshake blocker.

## 7. F81 closure criteria (unchanged, restated)

F81 closes when a REAL implementation (real topology + operator upstream
firewall) passes: the IP-layer probe, all four wave-25
`redteam.f81.*` probes, and the three wave-57 proxy probes registered
this wave. A design doc, a prototype, or passing only the mechanism
shape does not close it.

## 8. Open questions for Wave-58

1. Attempt the untried netns-handshake patterns (parent-prepared netns +
   setns-join in preexec; child-driven IFLA_NET_NS_FD move) and record
   which EPERM walls hold — or defer the topology to a privileged CI
   environment and say so.
2. Draft the mode-specific seccomp profile (AF_INET/AF_UNIX to the
   proxy's port only) as a coordinated change with `gov/sandbox.py`.
3. Specify the per-deployment upstream firewall contract (§6.4) so a
   deployment missing it is detectable, not silent.
4. Decide whether the proxy deserves a fuzzing wave (CONNECT parser +
   authority grammar) — cheap, high-value for bespoke userspace.
