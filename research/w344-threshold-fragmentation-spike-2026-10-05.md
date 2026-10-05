# RESEARCH SPIKE: threshold fragmentation for key custody (w344)

**Date:** 2026-10-05 · **Base:** 1a800558 · **Spend:** $0 · **Product code touched:** none
**Prototype:** `research/w344-fragspike/prototype.py` (stdlib only, run: `python3 research/w344-fragspike/prototype.py`)
**Source steal queue:** Outerlimit deep-dive (`deepdive-outerlimit/STEAL-BRIEF.md`, `deepdive-outerlimit/REPORT.md`)

## The spike question

Outerlimit fragments credentials so "no usable credential ever rests with an agent
or intermediary," reassembling only at the tool-invocation moment. Their scheme is
unpublished — this spike independently evaluates the idea against our
sentinel-substitution architecture: can we Shamir-fragment the **swap-side key
material** so the vault/proxy is no longer a single point of failure — the swap
needing k-of-n fragments, no single node holding enough to reconstruct?

**Scope decision:** fragment the **wrapping/master key K** (the swap-side key that
unwraps per-credential real values), never each credential. Per-credential
fragmentation multiplies share management by the credential count; the master key
is the actual single point of failure.

## What was built

A stdlib-only prototype: Shamir split (n=5, k=3) over GF(q) with Feldman VSS
commitments, toy fragment nodes that release shares only after a triple
attestation (identity + policy + execution context), Lagrange reconstruction at a
reassembly point, then unwrap of a toy credential. VSS group: runtime-generated
160-bit safe prime — **illustrative size only**; the spike measures protocol
mechanics, not cryptographic strength. Production needs q ≥ 256-bit (RFC 3526
group 14) and an audited implementation.

## Measurements (all stdlib, local)

| Operation | Cost |
|---|---|
| Split, dealer one-time (n=5, k=3) | ~960 µs |
| VSS share verification, per share | ~238 µs |
| Lagrange reconstruction (k=3) | ~9 µs |
| Fragment loss: 2 of 5 lost | reconstruct OK |
| Byzantine share (corrupted y) | **caught by VSS** |
| k−1 = 2 shares | information-theoretically useless (verified structurally) |
| Attestation denial (wrong host) | all nodes refuse release |

**The cryptography is the easy part.** Split/verify/reconstruct are microseconds.
The real costs are structural, not computational:

1. **k attestation round-trips per swap.** Every swap needs k fragment nodes to
   verify (identity + policy + execution context) and release. If nodes are local
   processes this is sub-millisecond; across hosts it is k network RTTs on the
   hot path of every tool call. Session-caching the reconstructed K amortizes
   this — but a session cache is a **transient single point of failure** again.
   There is no free lunch here, only a choice of where the window lives.
2. **The reassembly point is a transient SPOF.** Whoever runs reconstruction sees
   K *and* the unwrapped credential in the clear. Fragmentation removes the
   **persistent** single point of failure (theft at rest now needs k colluding
   nodes instead of one vault breach) but **moves** the trust to a transient
   window, it does not eliminate it. Actually eliminating it requires threshold
   decryption / MPC (decrypt under the shared key without ever reconstructing
   it) — an order of magnitude heavier and out of scope for this spike.
3. **Without VSS, one Byzantine fragment silently corrupts reconstruction.**
   Lagrange over a bad share yields the wrong K; the swap then fails closed
   (garbage unwrap) at best. Feldman/Pedersen VSS is **mandatory, not optional**.
4. **The dealer sees K.** The initial split needs distributed key generation
   (Pedersen DKG) or a documented trusted ceremony — the same class as our
   existing key ceremony. A "just run the dealer on the vault host" shortcut
   recreates the SPOF the whole exercise was meant to remove.
5. **Shares must be refreshed.** A static share set lets an attacker collect
   shares slowly over time. Proactive secret sharing (periodic re-randomization
   without changing K) is required for any long-lived deployment.

## Honest comparison with Outerlimit

Their fragment scheme, placement, reassembly location, and benchmarks are all
unpublished, so no claim of theirs can be verified or replicated. What this spike
establishes independently: the "no single point of failure" framing is only true
for **theft at rest**. Any reconstruction-based design has a transient reassembly
trust point; anyone claiming otherwise without threshold decryption is
hand-waving. Our placeholder model keeps one sharp edge regardless: the agent
never sees anything but sentinels, so prompt-injection exfiltration yields only
fake values — fragmentation protects the *store*, not the *use*, and the two
compose rather than compete.

## VERDICT: ADAPT-SELECTIVE (defer build, steal the language now)

**ADAPT the idea, but do not rebuild sentinel-substitution around it before v1.**
The security gain is real — the vault ceases to be a persistent single point of
theft; the bar becomes k colluding fragment nodes across trust domains — but the
price is five new trusted components (fragment nodes, VSS, DKG ceremony, share
refresh, reassembly enclave) and a per-swap k-attestation latency shape that
needs careful amortization. The current vault + HSM/Vault-transit posture is the
correct v1 answer; threshold fragmentation is the correct **v2 key-custody**
answer, sequenced after the evidence-envelope work.

**STEAL now (costs nothing):** the buyer language — "zero standing access," "no
usable credential ever rests with an agent or intermediary," "prevention, not
consequence-based controls." Adopt verbatim in positioning.

**DROP:** any claim that fragmentation "eliminates" the single point of failure
without threshold decryption; per-credential fragmentation; dealer-on-vault-host
shortcuts; session caching of reconstructed K without an explicit, auditable,
TTL-bound decision.

## Design rules for the future build lane

1. Fragment only the wrapping/master key. Never per-credential.
2. Feldman or Pedersen VSS mandatory; verify every share **before**
   reconstruction; refuse on any verification failure (fail closed).
3. No trusted dealer: Pedersen DKG for the initial split, or a documented key
   ceremony of the same rigor as the existing one.
4. Proactive share refresh on a schedule; refresh is a first-class operation,
   not an afterthought.
5. Reassembly in an ephemeral, memory-only process: mlock/VirtualLock, zeroize
   after use, never persist K, never log it. The transient window must be
   measured and documented, not wished away.
6. n ≥ 5, k = 3 minimum; fragment nodes in **separate trust domains**
   (different hosts/accounts) — k-of-n on one box is theater.
7. Never cache reconstructed K beyond a single tool-call window unless inside
   a TEE; session caching is an explicit, auditable, TTL-bound decision.
8. Keep the swap **decision** (policy engine approval) separate from fragment
   **release** (per-node identity+policy+context attestation). Conflating them
   recreates the SPOF.
9. The placeholder property is invariant: agents still only ever see sentinels;
   fragmentation is invisible to the agent and to the audit log.
10. Threshold decryption (MPC — use K without reconstructing it) is the v2 that
    actually eliminates the transient SPOF. The reconstruction-based design
    must document its transient window honestly until then.
11. Fragment-node attestation inputs (what verifies "execution context," who
    attests) are the annotation-arbitrage surface — same declaration→truth
    class as F426/F427. They need the same adversarial treatment, not trust.
