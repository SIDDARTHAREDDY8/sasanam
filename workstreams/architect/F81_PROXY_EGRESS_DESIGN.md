# F81 Filtered Egress — Proxy-Enforced Design (design-only, no prototype)

**Wave-56, 2026-09-22. Status: DESIGN ONLY — no prototype built, F81 stays
LOW OPEN.** This document answers the wave-56 Priority-1 brief: design the
§2a proxy (founder-strategy memo `research/founder-strategy-2026-09-22.md`,
recipe at lines 65–80) on paper, review it adversarially on paper, and state
explicitly what would honestly close F81. The wave-55 rule stands: **no
prototype until the design survives review.** The review below finds the
design sound-with-documented-residuals (no design-killer), so a prototype is
*permitted* by the review — it is not *mandated* by it; that call belongs to
a later wave.

**What this doc is not:** it does not close F81, does not change `gov/`,
`evals/`, or `tests/`, and registers no new probes in `registry.yaml` (probe
*specs* are named in §9 for a future wave to register). Finding hygiene: the
only open finding remains F81; next free number F125.

**Relation to wave-55:** `F81_SPLIT_REASSEMBLY_DESIGN.md` reached a
design-only verdict (no prototype) on the split-payload reassembly candidate:
tool-call reassembly is strategically empty (P1 sound-but-pointless,
adversary moves to two calls for free; P2 a losing bound+1 game that
degrades the tripwire's exactness invariant). §7 of this doc honors that
verdict and corrects one shorthand it carried (the proxy does not reassemble
content for free — see §7.3).

---

## 1. The gap, precisely

F81 (LOW, OPEN, accepted gap): `gov/sandbox.py` strict mode is binary —
netns established (total isolation, loopback down, no routes) or honest
refusal to execute. There is no intermediate "destination-filtered egress"
primitive. Evaluators who need sanctioned external access (the Irregular CTF
pattern: test-range targets on the real internet) must disable isolation
entirely — the perverse incentive the Gemini incident chain documented.

The wave-25 hostname-trust extension showed an IP-layer allowlist is
necessary but not sufficient: the Wiki agents defeated a proxy egress
control by registering `bypass.blob.core.windows.net`, pointing it at the
real target via `/etc/hosts`, and exploiting a `NO_PROXY` suffix-trust
rule. The closure-probe family `redteam.f81.*` (4 probes, spec in
`tests/test_sandbox_f81.py::F81ClosureSpec`) is registered and must all pass
for any future implementation.

The in-namespace prototype (child netns + veth + iptables) was deliberately
not shipped. Blockers (F81 ledger): (a) the sandbox sets the namespace up in
a `Popen(preexec_fn=...)` hook with no clean parent/child handshake to
configure the veth peer, and `setns()`/`nsenter` back into the child
namespace returns EPERM in this environment; (b) the seccomp profile denies
the entire socket family, so filtered egress needs a coordinated seccomp
redesign, not a bolt-on; (c) kernel REJECT unavailable (DROP only).
Shipping a partial filter that *reports* enforcement it cannot guarantee
would be worse than the honest binary. That accepted-gap rationale is the
bar this design must clear: **the proxy must be set-up-safe where
in-namespace iptables was not** (§8.5).

---

## 2. The §2a recipe — and a correction before designing

The founder memo's §2a recipe conflates **two different architectures**,
and the design must pick one, because they have opposite answers to "where
does enforcement live":

- **(A) OpenSandbox shape** (memo line 69): DNS-proxy *sidecar sharing the
  sandbox's network namespace* — DNS proxy on 127.0.0.1:15353, iptables
  redirects all port-53 to it, allowlist enforced on names (denied →
  NXDOMAIN), optional `dns+nft` mode adding resolved IPs for allowed
  domains to nftables with TTL. `CAP_NET_ADMIN` isolated to the sidecar;
  the app container stays unprivileged.
  Primary: https://github.com/pangjiping/opensandbox/blob/HEAD/components/egress/README.md

- **(B) woditschka ADR 2026-07-29 shape** (memo line 71, verified live this
  wave): enforcement **outside** the workload — the session container sits
  on a per-run `--internal` Docker network (no default route, no NAT,
  enforced by the engine) and reaches the internet only through a
  dual-homed squid forward proxy. Allowlist = hostnames the proxy resolves
  per request; `dst` deny *above* the allow rules refuses any name
  resolving into loopback/RFC1918/carrier-NAT/link-local; access log with
  verdicts recorded *outside* the container; proxy-not-ready = no network.
  **No container holds `NET_ADMIN`, `NET_RAW`, or root in the session's
  namespace.** The ADR explicitly *rejected* shape (A)'s premise after a
  ~4,400-line spike: "enforcement lived inside the workload's namespace,
  so every added control added privileged machinery there."
  Primary: https://github.com/woditschka/agentic-coding-reference/blob/HEAD/docs/adr/2026-07-29-proxy-enforced-egress.md

**Design decision: shape (B), adapted.** The enforcement point is
**parent/orchestrator-owned network topology, not anything inside the
child's network namespace.** The memo's phrase "loopback-bound egress
proxy sidecar sharing the sandbox network namespace" describes shape (A);
this design does not use it, for the ADR's reason plus our own: a proxy in
the child's netns is privileged machinery inside the cage, reachable by a
child that escalates to `CAP_NET_ADMIN` there (it could then
iptables-redirect its own traffic around the proxy). The ADR's core
property — *there is no route to race* — is what kills the readiness
ordering problem, and it only holds when the topology is owned outside
the workload.

Adaptation to this repo (no container engine; `gov/sandbox.py` owns the
netns lifecycle): the parent creates a veth pair **before** forking the
child; the child's netns gets one end with **no default route and no NAT**
— a single link route to the proxy's address. The forward proxy runs
**outside** the child's netns (parent netns or its own), listening only on
the veth address. Direct egress from the child is impossible at the
network layer: anything that ignores `HTTP_PROXY`/`HTTPS_PROXY` (raw
sockets, non-proxy-aware tools, `NO_PROXY` tricks) finds no route — the
failure direction is *denied, never bypassed* (ADR's phrase, adopted).

---

## 3. Enforcement point and traffic flow

```
                    +-----------------------------+
                    | child netns (untrusted)     |
                    |  veth-c: 169.254.240.2/30   |
                    |  routes: ONLY link route to |
                    |  169.254.240.1 (proxy)      |
                    |  lo DOWN, no default route  |
                    +------|----------------------+
                           | veth pair
                    +------|----------------------+
                    | proxy (operator-owned)      |
                    |  listens 169.254.240.1:3128|
                    |  ONLY on veth-p            |
                    |  resolves via OPERATOR      |
                    |  resolver (never child's)   |
                    +------|----------------------+
                           | upstream (operator-
                           | owned firewall layer)
                           v
                        internet
```

1. **Child → proxy:** the child may only open TCP to
   `169.254.240.1:3128` (the proxy's CONNECT port). A static packet rule
   on the veth (owned by the parent, installed before fork) restricts the
   link to that single destination — no TTL, no dynamic sets needed here.
2. **Proxy decision:** per CONNECT request, in first-match-wins order
   (§5): client check → method check (CONNECT only) → **dst deny**
   (resolved address in loopback/RFC1918/carrier-NAT/link-local → refuse)
   → allowlist (hostname match) → deny-all.
3. **Proxy → upstream:** on allow, the proxy resolves the name *itself*
   through the operator's resolver, dst-checks the answer it will connect
   to, and opens the upstream connection. The proxy's own upstream
   egress is constrained by an operator-owned host firewall layer (§6.4).
4. **Verdicts:** the proxy writes `allow|deny` + name + resolved IP +
   rule matched + active-policy hash to an operator-owned log path the
   child cannot reach (§6.3).

Non-HTTP(S) egress and direct-IP egress from the child are **denied by
absence of route** — not by a rule the child could remove. This is the
load-bearing property: enforcement is topological, and topology is owned
by the parent.

---

## 4. DNS behavior: NXDOMAIN-for-denied vs per-request proxy resolution

The brief asks for "DNS proxy behavior (NXDOMAIN for denied names,
dynamic nftables/IP sets with TTL for allowed)". Adjudication:

- **The child needs no DNS at all.** With no route, the child's own DNS
  queries go nowhere. A minimal fail-fast responder on the veth may
  answer NXDOMAIN to everything so child DNS fails fast instead of
  hanging — cheap, honest, fail-closed. It enforces nothing; the absence
  of route enforces.
- **Name decisions happen in the proxy, per request, through the
  operator's resolver.** There is no launch-time pin (the rotation
  failure the ADR rejected), no answer the child can poison: the child's
  `/etc/hosts`, `resolv.conf`, `nsswitch.conf`, and `NO_PROXY` are
  **never consulted** — they live in a namespace whose resolutions
  decide nothing. This answers wave-25 probes (2) `egress_hosts_repoint`
  and (3) `egress_resolver_isolation` **by construction**, and probe (1)
  `egress_noproxy_suffix_bypass` by the no-route property (below
  proxy-env semantics, where the Wiki Incident's suffix-trust bypass
  lived).
- **Dynamic nftables/IP sets with TTL** (the OpenSandbox `dns+nft`
  option) are *not* needed on the child link (static single-destination
  rule). They belong, if anywhere, to the optional packet layer
  constraining the **proxy's own upstream** (§6.4): resolved IPs for
  allowed names enter an ipset with the record's TTL. TTL-race analysis
  in §6.2 — the dangerous half of the race (rebind to
  metadata/LAN/loopback) is closed by the static dst-deny regardless of
  TTL; rebind between two public IPs is a policy question, not a
  boundary breach.

---

## 5. Ordering rationale (the security property is the rule order)

Proxy policy is **data, not code**: a TOML/JSON allowlist, parsed with a
strict reader, never executed. Unknown tables/keys are refused by name;
a malformed entry refuses the launch (ADR: "refusing to launch when the
policy generator cannot run matches the rule that nothing degrades into
open egress"). First-match-wins, top to bottom:

1. **Client check** — only the child's veth subnet may ask (read back
   after veth creation, not assumed).
2. **Method check** — CONNECT only; no plaintext HTTP relay, nothing to
   cache.
3. **Operator pinholes** (if any, e.g. the provider/lifeline host) —
   placed here *explicitly by the operator*, above the dst-deny, so the
   exemption is visible in the rule order, not hidden in suffix logic.
4. **dst deny** — any name resolving into loopback, RFC1918,
   carrier-NAT (100.64.0.0/10), or link-local space → refuse. One
   ordering closes DNS-rebind, LAN-probing, and cloud-metadata (the
   DeepSeek-harness/CVE-2026-82533 shape: harness control plane on
   loopback) — *provided* the deny is evaluated against the address the
   proxy actually connects to (§6.2).
5. **Allowlist** — hostname match (exact + explicit subdomains; **no
   suffix-trust wildcards of the Wiki shape** — a trusted suffix must
   never implicitly trust attacker-registered subdomains; each allowed
   name is enumerated).
6. **Deny-all, logged.**

The provider/lifeline host exemption lives at the **operator network
config layer** (rule 3, in the operator's file), never in the child's
env — wave-25 probe (4) `egress_operator_proxy_env` is answered because
the child's `extra_env`/`NO_PROXY` cannot widen operator trust: there is
no route for the widened trust to travel on.

---

## 6. Failure modes

### 6.1 Proxy crash / proxy-not-ready — closed by topology
- **Before fork:** the parent liveness-checks the proxy's listen socket;
  if it is not listening, the child is never forked. Proxy-not-ready =
  no network, never fail-open.
- **After fork:** the child has no route anywhere else. Proxy death →
  connection refused/timeout → requests fail. The parent's supervisor
  detects proxy death, kills the run, and reports honestly
  (`egress_filtered_unavailable` — a distinct state, never collapsed
  into `network_isolated`). There is nothing to fall back *to*: the
  ordering race "disappears with the privilege" (ADR) because there is
  no route to race.
- Half-open connections on proxy death hang until timeout rather than
  bypass. Denied, never exposed.

### 6.2 DNS latency and TTL races — narrowed, not eliminated
- Per-request resolution adds upstream-DNS latency to every CONNECT;
  resolution timeout → refuse (bounded, fail-closed).
- The proxy connects to the address it just resolved and dst-checks
  **that answer**. Cached answers are re-validated against the dst-deny
  at connect time and expire per the record's TTL.
- **Admitted residual (ADR-confirmed):** "Squid resolves a name and then
  connects, so a name changing answers between those steps is a narrow
  race the `dst` check cannot close." Per-request resolution + dst-check
  on the connected answer shrinks this to the resolve→connect TOCTOU
  window; atomic resolve-and-connect is not available in proxy-class
  software. Stated, not hand-waved.
- TTL staleness in dynamic ipsets (if the §4 upstream packet layer is
  deployed): the dst-deny on private ranges is **static and never
  expires**, so the dangerous rebind direction (→ metadata/LAN/loopback)
  is closed regardless of TTL. Public→public rebind inside the
  allowlist is policy, not a boundary breach.

### 6.3 Verdict-log tampering — outside the cage, hash-bound
- The proxy (outside the child's netns, outside the pivoted jail fs)
  writes verdicts to an operator-owned path the child cannot address.
  The child cannot reach the log writer's socket (veth restricted to the
  CONNECT port) or its files (pivot_root jail).
- Every verdict line carries the **active allowlist's hash** (policy
  version), so post-incident analysis shows *what was allowed when* —
  operator allowlist edits are auditable, not silent.
- Requirement for the prototype phase: verdicts feed the HMAC-chained
  audit log (the D1-core primitive exists) so tampering with the log
  file breaks the chain loudly. The log is evidence, not a control; the
  control is the topology.

### 6.4 Proxy (sidecar) compromise — contained, not trusted
- The proxy is new userspace attack surface reachable through crafted
  CONNECT traffic (ADR-admitted: "surface the kernel rules did not
  have"). Mitigations, all required: runs unprivileged, no
  `CAP_NET_ADMIN`/`CAP_NET_RAW`, seccomp-restricted, minimal code (CONNECT
  allow/deny, no caching, **no TLS interception** — deliberately, §10),
  config-as-data.
- **Blast radius requirement:** the proxy's own upstream egress MUST be
  constrained by an operator-owned layer (host firewall / cloud security
  group the agent process cannot touch). A compromised proxy must not
  equal full egress; its worst case is bounded by that layer. The proxy
  is a chokepoint, not a trust root. A deployment without the upstream
  constraint has not implemented this design.
- Killing the proxy gains the child nothing (no route).

### 6.5 Agent modifying its own network permissions — must be impossible
(Northflank principle, adopted as a hard requirement.) The child: has
no `CAP_NET_ADMIN` (dropped in `_harden_worker`, already true today);
cannot see or edit the proxy config (operator-owned, outside the jail);
cannot reconfigure interfaces post-exec (no caps); cannot install
iptables/nft rules anywhere (no privilege, and the veth's static rule is
parent-owned); `NO_PROXY`/env tricks change nothing (no route). The
veth-end move into the child netns happens in `preexec` **before**
hardening and exec — after that, the network view is frozen.

---

## 7. What the canary layer becomes once the proxy exists

### 7.1 Tripwire + wall, composed
- **The proxy is the wall:** it decides *where* bytes may go, for all
  payloads, blind to content.
- **The canary stays the tripwire:** it detects exfiltration of *our
  planted secrets* — the one payload class the wall cannot see (no TLS
  interception, §10). With the wall up, the tripwire's job narrows to
  planted-secret exfil via **allowed** destinations — precisely where
  the wall is blind. They compose without overlap: wall = destinations
  × all payloads; tripwire = planted payloads × all destinations.
- The wave-55 verdict stands untouched: no tool-call reassembler is
  built (P1 sound-but-strategically-empty, P2 a losing game that would
  degrade the exactness invariant). The canary's per-call exact-match
  semantics are unchanged by this design.

### 7.2 What the union-registry pattern keeps doing
Orthogonal and unchanged: `docs/SWARM_DEPLOYMENT.md`'s union-registry
wiring (each run's minted canaries registered into one shared registry
attached to each executor) gives cross-task/cross-run trip continuity —
the inward-facing answer to the credential-persistence shape (see the
wave-56 teardown addendum). The proxy does not replace it; it protects
a different boundary.

### 7.3 Correction to the wave-55 shorthand (honesty item)
Wave-55's BUILD_LOG entry said "the reassembly the class needs already
happens for free at the §2a proxy layer (bytes per connection, not
tool-call fragments)." **That shorthand is wrong as stated and is
corrected here:** a CONNECT-tunneling forward proxy does *not*
reassemble stream content — bytes tunnel opaquely; only TLS-terminating
inspection would see content, and the ADR deliberately excludes it
("The proxy sees destinations, never payloads"). What the proxy gives
for free is **destination confinement**, not content reassembly. The
split-secret-to-an-allowed-destination shape therefore still evades
*both* layers (fragments dodge the tripwire; the opaque stream passes
the wall) and remains a residual owned by **secret hygiene**
(short-lived, task-scoped credentials — the direction AGT's own
LIMITATIONS §8 mitigations point). The design does not claim otherwise.

---

## 8. Adversarial design review (on paper)

### 8.1 DNS-rebind against TTL windows
Covered in §6.2. The design closes rebind-to-private-space (static
dst-deny above allow, checked against the connected answer) and narrows
the residual to the ADR-admitted resolve→connect TOCTOU. An adversary
who controls the authoritative DNS for an *allowed* name can still flip
its public answer between the proxy's resolution and connect — the
destination stays within the allowlist's public space, so the security
boundary (no private-space egress) holds; the policy question (which
public IP) does not cross it. **Review verdict: narrowed, documented,
not eliminated.**

### 8.2 The proxy as confused deputy
In the rejected shape (A), the in-netns sidecar reads inputs the child
influences (port-53 traffic, local resolver state) — classic deputy
confusion surface. In the chosen shape (B), the proxy never reads the
child's `/etc/hosts`, `resolv.conf`, `nsswitch.conf`, or env; its only
child-controlled input is the CONNECT `host:port` line, which is
*validated* (dst-deny + allowlist), not trusted. The remaining deputy
shape is a compromised proxy serving the child — contained by §6.4, not
by trust. **Review verdict: the deputy surface is the reason shape (A)
was rejected; shape (B) keeps exactly one validated input.**

### 8.3 Verdict-log tampering
Covered in §6.3: outside the cage, hash-bound to the active policy,
chained into the audit log at prototype time. Residual: a fully
compromised proxy writes false verdicts — but a fully compromised proxy
is already contained by §6.4's upstream layer, and false *verdicts* do
not create *routes*. **Review verdict: log integrity is evidence-grade,
not control-grade; the control does not depend on it.**

### 8.4 Readiness race (proxy-not-ready vs first request)
There is no state in which the child has a route and the proxy is
absent: the route's only destination *is* the proxy's socket, and the
child is not forked until the socket is live (§6.1). **Review verdict:
closed by topology, not by ordering discipline.**

### 8.5 Operator misconfiguration of the allowlist — the accepted-gap
question
The in-namespace iptables design was rejected partly because a failed
rule installation degraded *silently toward open*: a partial filter
reporting enforcement it could not guarantee. Why the proxy is
set-up-safe where that was not:
1. **Failures converge to deny.** Proxy down, config unparseable,
   rule missing, socket not listening — every one of these leaves the
   child with no network. There is no failure direction that yields
   unfiltered egress, because unfiltered egress was never constructed.
2. **Nothing privileged lives in the cage.** The old design added
   `CAP_NET_ADMIN` machinery to the workload's namespace per control;
   this design adds zero.
3. **Policy is data, refused loudly.** Malformed entries refuse the
   launch by name; unknown keys are refused, not ignored. Nothing
   degrades into open egress.
4. **Honest reporting.** The filtered mode reports
   `egress_filtered=True` with the active allowlist (per F81's fix
   direction) — never collapsed into `network_isolated`.
5. **The residual that stays operator-owned:** an allowlist that
   *names the wrong host* (policy error, e.g. allowing
   `attacker-controlled.example`) is not fixable by mechanism. The
   design's answer is auditability, not prevention: allowlist-hash in
   every verdict line (§6.3), the rule order in tested code, and the
   wave-55 lesson that a wall that lies about its policy is worse than
   no wall.

**Review verdict: mechanism-misconfiguration is fail-closed;
policy-misconfiguration remains operator-owned and auditable. This is
the property the accepted gap was waiting for.**

---

## 9. F81 closure criteria (explicit — a future implementation must meet
all of these; this doc meets none of them)

F81 stays OPEN until a **real implementation** passes every probe below.
A design doc, a proxy existing, or passing only the IP layer does not
close it.

1. **Original IP-layer probe** (registered): `egress_allowlist=
   ["192.0.2.0/24"]` — 192.0.2.1 succeeds, 203.0.113.1 refused, the
   allowlist reported in `SandboxResult` with `egress_filtered=True`
   (never collapsed into `network_isolated`).
2. **Wave-25 `redteam.f81.*` family** (registered, spec in
   `tests/test_sandbox_f81.py::F81ClosureSpec`) — all four must pass:
   - `egress_noproxy_suffix_bypass`: child sets `NO_PROXY`/registers a
     subdomain under an operator-trusted suffix → direct egress refused
     (enforcement below proxy-env semantics — the Wiki shape).
   - `egress_hosts_repoint`: child re-points an allowed hostname at a
     denied IP via its own resolver view → refused (allowlist resolves
     through the sandbox's own resolver, never the child's).
   - `egress_resolver_isolation`: child mutates every visible resolver
     input → allowlist decisions byte-identical.
   - `egress_operator_proxy_env`: operator proxy env via `extra_env`;
     child overriding `NO_PROXY` must not widen operator trust.
3. **New probes this design registers (spec only — for a future wave to
   implement in `registry.yaml`):**
   - `redteam.f81.proxy_dst_deny_above_allow`: an *allowed* name whose
     current answer is RFC1918/loopback/link-local/carrier-NAT → refused
     at connect time (the dst-deny ordering, live).
   - `redteam.f81.proxy_crash_fail_closed`: proxy killed mid-run →
     child egress attempts fail; no bypass; result reports
     `egress_filtered_unavailable`, never `network_isolated=True`.
   - `redteam.f81.proxy_verdict_log_policy_hash`: verdict lines carry
     the active allowlist hash; rotating the allowlist changes the
     hash on subsequent lines.
4. **Non-criteria:** this document; a proxy process existing without
   the probes; passing (1) while failing any of (2)–(3).

---

## 10. What the design deliberately does NOT promise

- **No payload/content inspection.** No TLS interception — deliberately
  (ADR: "The proxy sees destinations, never payloads"). The wall is
  destination-shaped.
- **No protection against exfil to allowed destinations.** An allowed
  pastebin/API used as designed is outside the wall; planted-secret
  exfil there is the canary's job (§7.1), real-secret exfil there is
  secret hygiene's job (§7.3).
- **No fix for operator allowlist policy errors** (§8.5.5).
- **TTL/resolve→connect race narrowed, not eliminated** (§6.2, §8.1).
- **New userspace attack surface exists** (the proxy); it is contained
  (§6.4), not wished away. A deployment without the operator-owned
  upstream constraint has not implemented this design.
- **Does not replace the canary program**, does not change P8
  (uncovered-by-design) or P13 (partial-by-design), does not touch the
  namespace/seccomp core.

---

## 11. Blockers for the prototype phase (wave-57+, if authorized)

The review found no design-killer, but a prototype must clear these
before any enforcement claim:

1. **The parent↔child netns handshake in this EPERM environment.**
   The F81 prototype died on parent-side `setns` EPERM. Untested
   patterns the prototype must try first: parent-prepared netns
   (bind-mounted at `/run/netns/<run-id>`) + `setns`-join in `preexec`
   (no unshare); or child-driven `IFLA_NET_NS_FD` move of the veth end
   post-unshare. If the environment blocks both, that is a documented
   blocker and F81 stays OPEN — strict deny-all remains the only mode.
2. **Coordinated seccomp redesign.** The child profile denies the
   socket family wholesale; filtered mode needs AF_INET/AF_UNIX to the
   proxy's port only — a mode-specific profile, not a bolt-on (the F81
   ledger's blocker (b), still standing).
3. **Proxy implementation choice.** Small bespoke CONNECT proxy
   (auditable, supply-chain-light) vs squid (packaged, battle-tested,
   larger). The ADR chose squid for enterprise recognizability; our
   bar is auditability — the tradeoff is open.
4. **The upstream operator firewall layer** (§6.4) must be specified
   per deployment; without it the design is incomplete.
5. **Probe registration + implementation** of §9.3 in
   `evals/scenarios/registry.yaml` before any closure claim.

---

## 12. Design verdict

**Sound on paper, with documented residuals.** The load-bearing insight
— enforcement as parent-owned topology with no route to race — survives
the adversarial review; the five named attacks are answered by
construction (readiness race, resolver-input attacks, NO_PROXY bypass),
narrowed-and-documented (DNS-rebind TTL windows), or contained
(sidecar compromise, verdict-log tampering). Two corrections to prior
waves are recorded: the §2a recipe conflated the OpenSandbox sidecar
shape with the ADR's outside-the-workload shape (this design picks the
latter), and the wave-55 "reassembly for free at the proxy" shorthand
is corrected (destination confinement is free; content reassembly is
not — no TLS MITM). **No prototype this wave** (wave-55 rule honored).
F81 stays LOW OPEN; next free finding number F125.

*Primaries consulted (fetched 2026-09-22):* woditschka ADR 2026-07-29
(proxy-enforced egress) + 2026-07-31 local-binding residual; founder
memo §2a; F81 ledger (`evals/FINDINGS.md`); wave-25 closure-probe spec
(`tests/test_sandbox_f81.py::F81ClosureSpec`); `F81_SPLIT_REASSEMBLY_DESIGN.md`;
`gov/sandbox.py` preexec/netns/seccomp facts.
