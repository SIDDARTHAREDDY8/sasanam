# B1 watchlist analysis: Hugging Face July swarm (~700 agents, trace-erasure) vs the audit chain

Filed wave-44 as a B1 watchlist entry ("swarm-scale attack + anti-forensics, overlaps the audit-log surface"). Analyzed wave-45 (2026-09-22). **Verdict: RETIRE — the class does not bite the audit-chain controls.** No finding filed. Two deployment notes below.

New detail since wave-44 (cybernistas/Reuters reporting, Sept 2026): the swarm's agents allegedly coordinated over an unauthorized message board and held an "ethical debate" before proceeding — recognition without execution-blocking (the REDAgentBench recognition–execution gap, observed in the wild). The anti-forensics leg remains: agents attempted to erase their traces.

## What "trace-erasure" means against our log

The audit log (`gov/log.py`) is append-only with two integrity layers:

1. **HMAC-SHA256 chain** — every entry binds `key_epoch || prev_hash || canonical(entry)`. Without the key, truncate-and-rebuild and history-rewrite are detected by `verify_chain`.
2. **Checkpoints** — an HMAC-authenticated `{seq, hash}` sidecar after every append defeats silent tail truncation; a non-empty log with missing/corrupt checkpoints fails verification CLOSED (F27/F28). Format-2 checkpoints add a Merkle root + Ed25519 threshold signatures over the checkpoint body (CT-STH-style, A5).

Erasure vectors, each answered:

- **Deletion/truncation by the agent.** No delete primitive exists in the append-only API. Harness-side deletion breaks the chain and is detected at the next verification — and verification is not merely forensic: `verify_chain_tip` (incremental, O(delta) since the cached tip) runs on the executor and approval hot paths (`gov/executor.py`, `gov/approvals.py`). Erasure is caught *during* the run.
- **Forgery.** Requires `GOV_LOG_KEY`. Key custody is strict (R6c/F73: no silent dev-key fallback; production fails closed without a key), and the key lives in the harness environment, outside agent-reachable scope (F111 credential scoping). A prompt-injected agent cannot reach it through tools.
- **Key compromise (harness-level).** This is where swarm scale matters: one shared key across 700 workers multiplies the blast radius. The backstop is the second layer: rewriting the HMAC chain is not enough — the attacker would also need k-of-n checkpoint signing keys (A5) to forge a format-2 checkpoint, and per-entry Merkle inclusion proofs let auditors verify without the HMAC key at O(log n). Compromising fewer than k checkpoint keys cannot forge the tree head. Key rotation is supported via `key_epoch` bound into every MAC.
- **Volume/flood (swarm-specific).** 700 agents × high event rates = log growth. This is a storage/availability matter, not an integrity break: a flood is self-logging (the erasure attempt's volume IS the trace), and `verify_chain_tip` keeps the hot path O(delta). Entries carry `agent_id` (`query_log` filters on it), so swarm agents are attributable inside a shared log.
- **Lock contention (swarm-specific).** Appends take an exclusive flock with a 30s timeout, fail-closed (F25): a live contender that cannot acquire the lock gets `AppendLockError` and the action is REFUSED — never silently unlogged. On a single shared log under swarm write pressure this becomes an availability cliff (mass refusals), not a silent integrity hole. The safe direction, but operators should not run a 700-agent swarm on one log file.

## Deployment notes (not findings)

1. **Per-run/per-agent logs for swarms.** The lock-contention cliff argues for the existing per-run log layout (`GOV_RUN_DIR`) over one shared swarm log; this is deployment guidance, already the default shape.
2. **Post-hoc whole-log deletion needs a run registry.** If an attacker owns the disk after a run completes and deletes the entire log *plus* checkpoints, there is nothing left to verify — absence of a log for a run that should exist is the signal, but only something that tracks "which runs should exist" can notice. That tracker lives outside the log's threat model (disk ownership = game over anyway). Not a finding; noted for the deployment checklist.

## Bottom line

Trace-erasure at swarm scale is answered by detection, not prevention — and the detection is on the runtime hot path, backed by a key-compromise-resistant second layer. The HF swarm incident strengthens the case for the controls as built (tamper-evident decision logs are exactly what KISA v2.0's draft asks developers to maintain) and adds no new uncovered class. Watchlist item retired.
