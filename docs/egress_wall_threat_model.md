# Filtered-egress wall — residual threat model

**Scope:** the productized filtered-egress wall (F81 lab mechanism +
S7 launcher `gov/egress_launcher.py`). This document lists what the
wall does **not** stop. It is the honesty appendix to closing F136:
the launcher closes the *deployment* gap (no launcher, no pinning),
not the universe.

**What the wall does stop (validated):** direct IP-literal egress, DNS
rebinding, CNAME→metadata, metadata SSRF (direct and via proxy),
allowlisted-URL redirect to blocked destinations, DoH/direct-8.8.8.8
bypass, IPv6 escape, raw sockets, DNS tunneling to rogue resolvers,
unset-proxy direct connect — lab battery 17 STOPPED / 0 BREAK
(`evals/FINDINGS.md` F81, 2026-09-23). The launcher additionally stops:
launch with the wall down/partial, launch with any wall component
tampered (ruleset, allowlist, DNS config/zone, proxy artifact, seccomp
config), manifest/receipt tamper, and check→spawn races (child-side
preexec re-assert) — break battery `evals/s7egress_break.py`
16 CLOSED / 5 CONTROL.

## Residuals (accepted, documented — not fixed)

### R1. Covert channels through explicitly allowlisted destinations
An agent allowed to reach `example.com:443` can exfiltrate data *to*
`example.com:443`: DNS query names, TLS SNI, request sizes and timing,
and HTTP CONNECT is opaque by design. The wall is a *destination*
filter, not a *content* filter. Mitigation belongs to a different
layer (egress DLP on allowed destinations — `gov/dlp.py` — and
per-destination volume budgets), not to this wall.

### R2. DNS answers inside the allowlist are trusted (no DNSSEC)
The confined resolver answers authoritatively for allowlisted names,
but the upstream answers it forwards are not DNSSEC-validated (lab
had no DNSSEC; the sim's stub zone is static). A network-path attacker
who can spoof the confined resolver's upstream can rebind an
allowlisted name. Deployment requirement: run the confined resolver's
upstream over a trusted path or enable DNSSEC validation in dnsmasq.

### R3. Proxy and DNS are trusted computing base (TCB)
Compromise of the proxy or the confined resolver is a full bypass —
they speak for the wall. The launcher's digest pinning detects
*on-disk* tamper of their configs/artifacts at startup, but a
runtime memory compromise of either process is outside this control.
Deployment requirement: run both as isolated, minimal-privilege
processes (separate UIDs, read-only config mounts), and monitor them
as TCB (unexpected restart / binary change = incident).

### R4. Host root bypasses everything
A privileged process on the host can enter the netns, rewrite
nftables, or ptrace the agent. The wall raises the cost for the
*agent* threat model (a compromised agent process); it is not a
defense against a compromised host. The launcher's pinning assumes
the install-time environment was trustworthy — a rootkit present at
install pins the attacker's wall.

### R5. Data hidden in allowed destinations (R1's payload twin)
Even with DLP, steganographic exfiltration to an allowlisted
destination (e.g., encoded in uploaded images, TLS padding) is not
stoppable by a destination filter. The wall answers "where may the
agent talk", never "what may it say".

### R6. Allowlist operator error
The allowlist is the entire outside world. An overly broad entry
(`*.example.com:443`, a CDN fronting attacker content, an IP that
later changes hands) silently widens the wall. The launcher pins the
allowlist *bytes*, not its *wisdom*. Deployment requirement: treat
allowlist changes as policy changes (review + approval, cf.
`gov/policy_change.py`); prefer exact `host:port` entries; never
suffix wildcards (the F81 Wiki lesson: `*.blob.core.windows.net`
suffix trust was the bypass).

### R7. TOCTOU below the preexec→exec window
The launcher closes check→spawn (interprocess lock + child-side
preexec re-assert). What remains: the wall dying *inside* the child
between the preexec re-assert and exec (nanoseconds, single process),
and the wall dying *after* launch while the child runs (the wall is
not re-checked for the child's lifetime). A long-lived agent process
outlives its launch-time attestation. Deployment requirement: for
long-lived agents, re-verify wall state on a heartbeat and kill the
child group on wall loss (not implemented in this wave).

### R8. Child-side name resolution is the wall's, not the child's
By design the allowlist decision resolves through the confined
resolver only. If a deployment ever lets the child influence
resolution (custom `/etc/hosts`, `LD_PRELOAD` getaddrinfo shim), the
Wiki/F81 repoint attacks return. The launcher scrubs proxy-env
wideners from the child env, but a deployment that bind-mounts a
writable `/etc/hosts` into the jail re-opens it. Keep the jail's
resolver inputs read-only.

### R9. The sim is a mechanism model, not a topology proof
`evals/s7egress_break.py` runs against localhost fixtures (stub
proxy/DNS, `FakePacketFilter`). It proves the *launcher* (pinning,
fail-closed startup, preexec race) and the *mechanism shape*
(allowlist enforcement, confined resolution). It does not re-prove
the netns/nftables/seccomp topology — the GCP lab did
(`~/workspace/f81-lab-evidence/`). Any change to the *topology*
(netns setup, nftables backend, seccomp profile mechanics) needs a
new privileged lab run, not just this battery.

### R10. Receipt custody
The install receipt is the trust anchor: whoever can rewrite the
receipt *and* the manifest can re-pin a malicious wall. Protect the
receipt like a key (offline copy, separate custody from the wall
host). The launcher cannot distinguish "operator re-pinned" from
"attacker re-pinned" — that distinction is procedural.

### R11. Long-lived wall, short-lived pins
Component digests are verified at *launch* time. A component tampered
*after* a child's launch is not detected until the next launch.
Because the proxy and confined resolver re-read their config files per
request, such tamper is live-exploitable by the already-running child
without any new launch; the tamper is caught loudly
(`component_tampered`) at the next launch — after the fact. Pair with
runtime integrity monitoring for high-assurance deployments.

## Non-goals (never claimed)
- Content inspection of allowed traffic (DLP layer's job).
- Protection against host compromise or malicious operators.
- Availability: the wall fail-closes, so wall outages are agent
  outages by design. That is the correct tradeoff, stated openly.
