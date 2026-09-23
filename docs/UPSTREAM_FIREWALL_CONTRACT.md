# Upstream firewall contract (F81 filtered-egress deployments)

Normative. No marketing. This contract exists because the proxy is a
*policy decision point*, not a firewall: a compromised or buggy proxy
must still be unable to move bytes to arbitrary destinations. The
operator-owned upstream firewall is the layer that guarantees that.
**A deployment without this layer has not implemented the F81 design**
(`gov/egress_proxy.py` module docstring; wave-56 ADR §6.4).

## 1. Definitions

- **Proxy**: the CONNECT-tunneling decision engine (`gov/egress_proxy.py`).
- **Upstream firewall**: operator-owned packet filtering *outside* the
  cage and *outside* the proxy process, on the path between the proxy's
  upstream socket and the real network. It independently permits only
  the destination classes the allowlist can ever produce (public IPs on
  allowed ports — never loopback/RFC1918/link-local, regardless of what
  the proxy asks for).
- **Firewall state**: one of `verified`, `degraded`, `absent`.

## 2. Startup checks (normative)

The launcher MUST perform all of the following before `mark_ready()`.
Any failure → the proxy never becomes ready, the child is never forked,
and the run reports `egress_filtered_unavailable` (never silently open,
never collapsed into `network_isolated`).

1. **Forwarding off.** `/proc/sys/net/ipv4/ip_forward` MUST read `0`
   (and `ip_forward` for IPv6 MUST be `0` / `default_forwarding` off
   where applicable). This is asserted, not assumed — Lane 1 showed a
   child-side default route terminates at the parent end, which is only
   a dead end if the parent forwards nothing.
2. **Veth-end exclusivity.** The parent veth end MUST have exactly one
   IPv4 address (the proxy's), MUST NOT be a bridge member, and MUST
   have no other listener bound to it. Enumerate, don't assume.
3. **Operator firewall check command.** The deployment configuration
   MUST name an operator-owned executable check (absolute path, owned
   by the operator uid, not group/other-writable). The launcher runs it
   at startup; exit 0 with the token `UPSTREAM_FIREWALL_OK` on stdout
   means `verified`. Any other outcome means `degraded` (non-zero exit
   but the command ran) or `absent` (command missing/unexecutable —
   this MUST be treated as `absent`, not retried silently).
4. **Freshness.** The check MUST have run within the configured TTL
   (default 24h). A stale `verified` is `degraded`.

The proxy itself MUST NOT consult any environment variable, file, or
flag for this state — it receives the state from the launcher through
its constructor/wiring only (same rule as the verdict-log path:
no env-var override ever).

## 3. Audit (absent/degraded is DETECTABLE, never silent)

- Every run's status MUST carry `upstream_firewall` with exactly one of
  `verified` / `degraded` / `absent`. The field MUST NOT be omitted when
  the check was not performed: not performing it IS the `absent` state.
- Every verdict-log line SHOULD carry the run's `upstream_firewall`
  state (via the logger's `extra` channel), so post-incident analysis
  can distinguish "proxy allowed X with firewall verified" from
  "proxy allowed X with no firewall".
- `degraded` MUST emit an operator-visible warning at startup naming
  which check failed. `absent` MUST emit the error in §4.
- A run with `upstream_firewall: absent` MUST NOT be reported as a
  filtered-egress run without qualification: the honest status is
  `egress_filtered: true` + `upstream_firewall: absent` — two separate
  facts, never merged.

## 4. Operator-facing error (exact text)

When the check is absent or fails at startup, the launcher MUST refuse
with:

```
F81-UPSTREAM-FIREWALL: refusing to launch filtered egress: upstream
firewall state is '<absent|degraded>' (<reason>). The proxy is a policy
decision point, not a firewall; without the operator-owned upstream
layer this deployment has not implemented the F81 design. Fix the
firewall check '<check-path>' and relaunch. The child was not forked.
```

`<reason>` names the failing check from §2 (e.g.
`ip_forward=1`, `check exited 3`, `check not executable`,
`state older than TTL`).

## 5. Non-goals

- This contract does not specify *which* firewall (iptables/nftables/
  cloud SGs) — that is per-deployment. It specifies the *detectability*
  of its absence.
- It does not cover content inspection: the proxy tunnels opaquely by
  design (no TLS interception). The firewall is destination-confinement
  defense in depth, not DLP.
- The prototype's `FilteredRun.status()` reports
  `upstream_firewall: "unverified (no contract check wired)"` until a
  deployment wires §2 — the absence is visible in the prototype's own
  reporting rather than silently defaulting to `verified`.
