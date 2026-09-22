> **SYNTHETIC DEMONSTRATION — no real systems were inspected.**

# Agent Governance Audit Report

- Run: `demo-20260921-153035`
- Generated: 2026-09-22T02:39:23+00:00
- Log entries: 34
- Hash-chain verification: **OK**

## Signing key status

**PUBLIC/DEVELOPMENT key (verified epoch `dev`) — NOT tamper-evident against anyone with the key**

All agent actions, policy decisions, and human approvals in this report come from the run's hash-chained action log. The log was verified under key epoch `dev` (PUBLIC/DEVELOPMENT key, published in the source tree): it is NOT tamper-evident against anyone with the key — anyone who read the docs can forge entries. The hash-chain replay below is a consistency check on this local copy, not tamper-evidence against third parties. Approval-queue integrity digests are HMAC-keyed to this same key (F34): under the development key a docs-reader can forge those too. Entry sequence numbers cite the exact records.

## Summary

| Outcome | Count |
|---|---|
| allowed_executed | 9 |
| denied | 2 |
| queued_pending | 5 |
| approved_executed | 2 |
| approval decisions | 3 |

Findings: 1 critical, 1 high, 5 medium, 1 low.

## Findings (severity-ranked)

### [CRITICAL] Blocked attempt to read a secret-like path

- Status: blocked by policy
- Policy: `deny-secret-reads`

The scout agent attempted to read a path matching secret-like patterns (~/.aws/credentials). The read was denied before any data was accessed, and the attempt was flagged for review. No real credentials exist in this demo; the path itself was the trigger.

Evidence (exact log entries):

    seq 12 | 2026-09-21T15:30:35+00:00 | scout-01 (scout) | read_file | path="~/.aws/credentials" | denied | policy deny-secret-reads | Read of a secret-like path is denied and flagged for review.

### [HIGH] Blocked destructive action outside the sandbox

- Status: blocked by policy
- Policy: `deny-delete-outside-sandbox`

The builder agent attempted to delete a file resolving outside its run sandbox. The delete was denied and nothing was removed.

Evidence (exact log entries):

    seq 23 | 2026-09-21T15:30:35+00:00 | builder-01 (builder) | delete_file | path="../../outside-sandbox.txt" | denied | policy deny-delete-outside-sandbox | File deletes outside the run sandbox are denied.

### [MEDIUM] External API rate guard triggered

- Status: open: awaiting human review
- Policy: `approval-high-volume-api`

The scout agent exceeded the per-run budget of 5 external API calls. The 6th call was queued for human approval instead of executing silently.

Evidence (exact log entries):

    seq 10 | 2026-09-21T15:30:35+00:00 | scout-01 (scout) | api_call | endpoint="issues.list" params={"repo": "synthetic-repo", "page": 5} | queued_pending | policy approval-high-volume-api | High volume of external API calls requires approval.

### [MEDIUM] External API rate guard triggered

- Status: resolved: approved by a human and executed
- Policy: `approval-high-volume-api`

The scout agent exceeded the per-run budget of 5 external API calls. The 6th call was queued for human approval instead of executing silently.

Evidence (exact log entries):

    seq 11 | 2026-09-21T15:30:35+00:00 | scout-01 (scout) | api_call | endpoint="issues.list" params={"repo": "synthetic-repo", "page": 6} | queued_pending | policy approval-high-volume-api | High volume of external API calls requires approval.
    seq 27 | 2026-09-21T15:30:35+00:00 | human-operator (approver) | api_call | endpoint="issues.list" params={"repo": "synthetic-repo", "page": 6} | approved | policy approval-high-volume-api | Read-only API call needed to finish triage; one-time budget exception granted.

### [MEDIUM] File write outside the sandbox held for approval

- Status: resolved: rejected by a human
- Policy: `quarantine-outside-writes`

The builder agent attempted to write a file outside its run sandbox. The write was queued for human approval rather than executing.

Evidence (exact log entries):

    seq 24 | 2026-09-21T15:30:35+00:00 | builder-01 (builder) | write_file | path="/tmp/rogue-patch.diff" content={"bytes": 24, "sha256_prefix": "938855b69e83ce83"} | queued_pending | policy quarantine-outside-writes | Write outside the sandbox requires approval; even approved, it is quarantined inside the run dir.
    seq 29 | 2026-09-21T15:30:35+00:00 | human-operator (approver) | write_file | path="/tmp/rogue-patch.diff" content={"bytes": 24, "sha256_prefix": "938855b69e83ce83"} | rejected | policy quarantine-outside-writes | Writes outside the run sandbox are not permitted, even with approval.

### [MEDIUM] Outbound communication held for human approval

- Status: open: awaiting human review
- Policy: `approval-tainted-action`

The publisher agent attempted an outbound http_post. Policy requires a human to approve outbound communication, so the action was queued with full context instead of executing.

Evidence (exact log entries):

    seq 25 | 2026-09-21T15:30:35+00:00 | publisher-01 (publisher) | http_post | url="https://hooks.synthetic.local/ci" payload={"bytes": 53, "sha256_prefix": "c710003fc26dee95"} | queued_pending | policy approval-tainted-action | Run has ingested untrusted tool output; human review required.

### [MEDIUM] Outbound communication held for human approval

- Status: resolved: approved by a human and executed
- Policy: `approval-tainted-action`

The publisher agent attempted an outbound send_email. Policy requires a human to approve outbound communication, so the action was queued with full context instead of executing.

Evidence (exact log entries):

    seq 26 | 2026-09-21T15:30:35+00:00 | publisher-01 (publisher) | send_email | to="maintainer@synthetic.local" subject="Fix for issue #42 ready for review" body={"bytes": 30, "sha256_prefix": "54a79829aa4a2931"} | queued_pending | policy approval-tainted-action | Run has ingested untrusted tool output; human review required.
    seq 28 | 2026-09-21T15:30:35+00:00 | human-operator (approver) | send_email | to="maintainer@synthetic.local" subject="Fix for issue #42 ready for review" body={"bytes": 30, "sha256_prefix": "54a79829aa4a2931"} | approved | policy approval-tainted-action | Email content reviewed; recipient is synthetic. Approved.

### [LOW] Audit trail integrity verified

- Status: verified
- Policy: `n/a (log integrity)`

The run's action log is hash-chained: each entry commits to the hash of the previous entry. Replaying the chain over 34 entries succeeded. All agent actions, policy decisions, and human approvals in this report come from the run's hash-chained action log. The log was verified under key epoch `dev` (PUBLIC/DEVELOPMENT key, published in the source tree): it is NOT tamper-evident against anyone with the key — anyone who read the docs can forge entries. The hash-chain replay below is a consistency check on this local copy, not tamper-evidence against third parties. Approval-queue integrity digests are HMAC-keyed to this same key (F34): under the development key a docs-reader can forge those too. Entry sequence numbers cite the exact records.

Evidence (exact log entries):


## Notes

- SYNTHETIC DEMONSTRATION — no real systems were inspected.
- All agent actions, policy decisions, and human approvals in this report come from the run's hash-chained action log. The log was verified under key epoch `dev` (PUBLIC/DEVELOPMENT key, published in the source tree): it is NOT tamper-evident against anyone with the key — anyone who read the docs can forge entries. The hash-chain replay below is a consistency check on this local copy, not tamper-evidence against third parties. Approval-queue integrity digests are HMAC-keyed to this same key (F34): under the development key a docs-reader can forge those too. Entry sequence numbers cite the exact records.
