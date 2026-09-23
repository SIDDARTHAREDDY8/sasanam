# F81 netns handshake — wave-58 attempt log and hardened spec

Status: **WORKS-HARDENED with one environmental leg missing.** Both untried
patterns from wave-56 were attempted in this environment (Linux, euid 0,
reduced capabilities — `CapEff=0x1fffff7ffff`, container). Neither behaved
as wave-56 predicted: `unshare(CLONE_NEWNET)` in a forked child
**succeeds** here, so the real handshake pattern is child-driven unshare,
not parent-prepared + setns-join. Every claim below is from an executed
attempt, with errno evidence. Attempt scripts: `/tmp/netns_attempt.py`,
`/tmp/netns_handshake.py`, `/tmp/netns_e2e.py`, `/tmp/netns_proxyreach.py`,
`/tmp/netns_eperm_scope.py` (ephemeral; results transcribed here).

## 1. Attempt log (errno evidence)

| # | Attempt | Result |
|---|---------|--------|
| A | Parent-prepared: `unshare(CLONE_NEWNET)` in forked child (ctypes + `os.unshare`) | **SUCCEEDS** — child exits 0, `unshare` rc=0 errno=0 |
| A2 | Sibling setns-join: second child `setns(/proc/<holder>/ns/net, CLONE_NEWNET)` | **FAILS** — `EPERM` (errno 1) |
| A3 | Baseline `setns` to own netns (`/proc/self/ns/net`) | **FAILS** — `EPERM` (errno 1). Even self-join is denied here. |
| B1 | `ip netns add w58probe` (named netns, needs bind-mount) | **FAILS** — `EPERM` (`setns: Operation not permitted` from the bind-mount step) |
| B2 | `RTM_NEWLINK`: `ip link add w58v0 type veth peer name w58v1` | **SUCCEEDS** — rc=0, link visible |
| B3 | `RTM_SETLINK`: `ip link set w58v1 netns <holder-pid>` (move peer into the unshared child's ns) | **SUCCEEDS** — rc=0 |
| C | End-to-end: child self-unshares, parent injects veth peer, child configures `lo`+`veth-c` itself | **SUCCEEDS** — child sees only `lo` + `w58c`; route table is exactly `169.254.240.0/30 dev w58c proto kernel scope link` — **no default route** |
| D | Child TCP to outside (`93.184.216.0:80`) | `ENETUNREACH` (errno 101) — the wall holds |
| E | TCP/UDP from child to parent veth end (`169.254.240.1`) | **`EPERM` (errno 1) — ENVIRONMENTAL.** The parent itself gets `EPERM` connecting to its *own* veth address (`10.99.99.1`, `192.168.99.1`, `169.254.240.1` all EPERM), while parent→`127.0.0.1` CONNECTs and parent→external `93.184.216.0:80` CONNECTs. iptables is wide open (all ACCEPT). Something in this environment (LSM/eBPF) vetoes `connect()` to locally-created veth addresses. The proxy-over-veth leg therefore **cannot be exercised here** — deployment-verified-only. |

Consequence: wave-56's "parent-prepared netns + setns-join" is **not** the
pattern — setns is EPERM even to self. The working pattern is:

**child-driven unshare + parent veth injection**: the launcher forks; the
child calls `unshare(CLONE_NEWNET)` itself (works); the parent creates the
veth pair, addresses + raises its own end, and moves the peer into the
child's netns by PID (`RTM_SETLINK ... netns <pid>`, works); the child
self-configures (`lo` up, peer address, link up). No `setns` anywhere, no
named netns, no bind mounts.

## 2. Break-first battery (all executed against the E2E cage)

| Attack | Result |
|--------|--------|
| Cage escape: child `setns(/proc/1/ns/net)` | **blocked, EPERM** |
| Cage escape via fresh userns (`unshare(CLONE_NEWUSER)` then `setns`) | **blocked, EACCES** |
| Child widens routing: `ip route add default via 169.254.240.1` | **blocked, EPERM** (`RTNETLINK answers: Operation not permitted`). Not relied upon (see §4.4) — the wall is the parent's forwarding posture. |
| fd leakage: `/proc/self/fd` in child | Only stdio + harness pipes; **no netns fds, no listening sockets**. Hardening rule §4.2. |
| Unix abstract sockets across the ns boundary | **NOT demonstrated**: child `connect("\0w58parent")` → `ECONNREFUSED` (111). That return only means no listener was bound at that name in the namespace the child resolved — it does NOT prove the abstract-socket namespace is shared across netns (an unbound name in the child's own ns returns the same error). No successful cross-netns abstract-socket connection was ever observed. Hardening rule §4.3 bans them conservatively anyway. |
| Raw sockets inside the child ns | Creatable, harmless: only the child's own ns is reachable. |
| Parent reachability from child: child → parent-ns `127.0.0.1:18082` | `ECONNREFUSED` — namespaces properly split. |
| `ip_forward` in this environment | `0`. Deployment must assert this (§4.4). |
| Peer lifecycle | When the child ns dies, its veth end vanishes; launcher must delete the parent end and treat a dead peer as cage-teardown, never as "route via another interface". |

## 3. What remains deployment-verified-only

The **proxy-over-veth data leg**: the child must TCP-connect to the proxy
on the parent veth end, and the proxy must accept only on that address.
Row E above shows this exact syscall is vetoed by this environment even
parent-side, so no honest test of it can run here. A privileged CI
environment must implement: (a) a real listener on the parent veth end,
(b) child CONNECT through it, (c) negative: child CONNECT to any other
address:port fails, (d) negative: killing the proxy yields
`egress_filtered_unavailable`, never silent open.

## 4. Hardened handshake spec (normative for the launcher)

**4.1 Pattern.** Child-driven unshare only. The launcher MUST NOT pass a
netns file descriptor to the child, MUST NOT use `setns` in either
direction, and MUST NOT rely on named netns (`ip netns` bind-mounts).

**4.2 fd hygiene.** Before fork, the launcher sets `CLOEXEC` on every fd
it holds (netlink socket, listen sockets, log fds). The child inherits
exactly: stdin/stdout/stderr (or `/dev/null`), the ready/go/report pipes
(or an equivalent status channel), and nothing else. Verified in the
battery: no netns fd, no listening socket reached the child.

**4.3 No abstract unix sockets.** Abstract sockets are banned
conservatively (battery row 5): no successful cross-netns
abstract-socket connection was ever demonstrated — the observed
`ECONNREFUSED` does not prove visibility — but the launcher and the
proxy MUST use only pathname unix sockets (restrictive parent dir,
`0700`) or the veth TCP address — never `\0name` abstract sockets — so
a child can neither impersonate nor probe launcher services, and no
covert parent↔child channel exists outside the proxy leg.

**4.4 Parent-end posture (feeds the Lane-3 firewall contract).**
`/proc/sys/net/ipv4/ip_forward` MUST be `0` (assert at startup; refuse to
launch otherwise). The parent veth end MUST NOT be a bridge member and
MUST have no address other than the proxy's. The child cannot add routes
here (EPERM in this environment) but the design does not rely on that:
even a child-side default route via the parent end terminates at a dead
end — the parent forwards nothing and the only listener is the proxy.

**4.5 Teardown.** Parent-end deletion is part of cage teardown; a vanished
peer is cage death, never a fallback to another path.

## 5. Verdict

**Works-hardened, one leg deferred.** The isolation primitive (fresh netns
per child, no default route, single link route to the parent end) is real
and break-first-tested in this environment — it is no longer
"deployment-only" as a mechanism. What stays deployment-only is the
proxy-over-veth data leg (environmental EPERM on `connect()` to veth
addresses, §1 row E) and therefore F81 itself stays OPEN. `EmulatedCage`
in `gov/egress_proxy.py` is unchanged this wave: the mechanism-shape
prototype does not claim the topology, and the topology's last leg still
needs a privileged CI per §3. No finding filed (no independently-reachable
miss in shipped code; the abstract-socket visibility is a deployment
hygiene rule, recorded as a boundary note, not a finding).
