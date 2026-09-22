# `gov/bridges/` — D1 bridge adapters (A12)

The durable approval queue (`gov/approvals.py`) is the human-decided
core. This package holds the THIN adapters that make that core
addressable from foreign agent runtimes — Microsoft AGT and AWS
AgentCore — per `workstreams/architect/ADJUDICATIONS.md` A12.

## What's here

| Module | Status | Contract |
|---|---|---|
| `core.py` | **this wave** | `BridgeAdapter` ABC (`request_approval` / `wait_for_decision` / `abort`) + shared fail-safe helpers (`bounded_wait`, `deny_decision`, `compute_request_digest`) + `BridgeHandle`. Every bridge gets identical fail-safe semantics; do not reimplement them. |
| `agt.py` | **this wave** | In-process `DurableQueueApprovalHandler` implementing AGT-Python's `ApprovalHandler` interface shape (`request_approval(context) -> decision`), duck-typed — the AGT SDK is never imported, so this loads with or without AGT installed. Default wait 240s, strictly under AGT's 5-min CallbackApproval default. |
| `aws.py` | sequenced later | The corrected A12 direction: we are an approval-event **PRODUCER** into the trajectory, never a consumer of AWS approval webhooks (AWS emits none — any "receive AWS approval events" work item is rejected at dispatch). Ships with `FakeGateway`; live validation is an operator-side checklist, never a CI gate. |
| `agt_webhook.py` | sequenced later | AGT .NET `WebhookApprover` HTTPS ingress (mTLS/HMAC, idempotency on their `ApprovalRequestId`, versioned-schema validation). **Not started until the JSON schema is pinned from their .NET source** — protocol research first. |

## Queue contract (the only surface bridges may call)

`ApprovalQueue.queue_external(...)` → approval id (idempotent on
`external_request_id`; foreign digests MAC-bound into the record),
`ApprovalQueue.wait_for_decision(approval_id, timeout_s)` →
`"approved" | "rejected" | "timeout"` (timeout expires the bridge wait
via `mark_bridge_expired()`; the record stays pending and late
decisions are audit-only, never executable — T11/T12), and
`ApprovalQueue.get_record(...)` (detached read-only copy).

Execution ownership: a record carrying `bridge_id` is
**foreign-executed** — the foreign runtime executes on its side after
our human decides. Our own `execute_approved()` sweep never executes
bridge records (bridge-expired ones are refused loudly per T12/F85;
healthy ones are skipped after the integrity checks).

## Rules every bridge follows

1. **Fail-safe deny.** Only an explicit human `"approved"` becomes an
   approval. Timeouts, rejections, and every queue-side failure map to
   deny (`bounded_wait`).
2. **Strictly-shorter waits.** Our bounded wait must lapse before the
   foreign runtime's own approval timeout, or the foreign side gives up
   first and our wait is pointless.
3. **No trust in foreign framing.** Caller DIDs, justifications, and
   arguments are recorded verbatim as UNVERIFIED; the human sees only
   the bridge-generated preview.
4. **No execution.** Bridges never execute anything and never bypass
   the queue's decision paths.
5. **Terminology guard (A12, binding).** "Approval delegation" =
   D1-core human reassignment of decision stewardship. "Authority
   delegation" = P10 agent-to-agent grant of tool-call authority.
   Bridges do neither — they *request* a human decision and *wait*.
   Never use "delegation" for bridge behavior in code, docs, or audit
   fields.

## Deployment contract (D5)

Until real auth + TLS + KMS-backed keys are in place: **in-process
shim only, no network ingress**. The web console renders bridge-queued
records with a `bridge:<id>` badge and read-only foreign
digests/versions (badge UI landed wave-25 in `gov/approval_web.py`:
list badge, detail panel, unmistakable bridge-expired rendering, and
an UNVERIFIED BRIDGE fail-closed warning when bridge markers lack a
verifiable `bridge_id`). No bridge-specific auth bypass in the console.

## Honest limits

- The foreign request digest is **tamper-evidence, not attestation**:
  we share no secret with the foreign runtime and cannot verify the
  digest against it. Post-queue tampering breaks our MAC and is
  refused.
- The AGT interface shape here is duck-typed against A12's contract,
  not integration-tested against the SDK (no live AGT dependency in
  this repo; `$0` standing order). The `.NET` protocol shape is
  explicitly unverified — that research is sequenced last for a
  reason.
