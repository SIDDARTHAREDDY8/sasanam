> **SYNTHETIC DEMONSTRATION — no real systems were inspected.**

# Agent Governance Audit Report

- Run: `demo-20260921-142522`
- Generated: 2026-09-21T14:25:22+00:00
- Log entries: 23
- Hash-chain verification: **OK**

## Summary

| Outcome | Count |
|---|---|
| allowed_executed | 10 |
| denied | 2 |
| queued_pending | 4 |
| approved_executed | 2 |
| approval decisions | 3 |

Findings: 1 critical, 1 high, 4 medium, 1 low.

## Findings (severity-ranked)

### [CRITICAL] Blocked attempt to read a secret-like path

- Status: blocked by policy
- Policy: `deny-secret-reads`

The scout agent attempted to read a path matching secret-like patterns (~/.aws/credentials). The read was denied before any data was accessed, and the attempt was flagged for review. No real credentials exist in this demo; the path itself was the trigger.

Evidence (exact log entries):

    seq 8 | 2026-09-21T14:25:22+00:00 | scout-01 (scout) | read_file | path="~/.aws/credentials" | denied | policy deny-secret-reads | Read of a secret-like path is denied and flagged for review.

### [HIGH] Blocked destructive action outside the sandbox

- Status: blocked by policy
- Policy: `deny-delete-outside-sandbox`

The builder agent attempted to delete a file resolving outside its run sandbox. The delete was denied and nothing was removed.

Evidence (exact log entries):

    seq 14 | 2026-09-21T14:25:22+00:00 | builder-01 (builder) | delete_file | path="../../outside-sandbox.txt" | denied | policy deny-delete-outside-sandbox | File deletes outside the run sandbox are denied.

### [MEDIUM] External API rate guard triggered

- Status: resolved: approved by a human and executed
- Policy: `approval-external-rate-guard`

The scout agent exceeded the per-run budget of 5 external API calls. The 6th call was queued for human approval instead of executing silently.

Evidence (exact log entries):

    seq 7 | 2026-09-21T14:25:22+00:00 | scout-01 (scout) | api_call | endpoint="issues.list" params={"repo": "synthetic-repo", "page": 6} | queued_pending | policy approval-external-rate-guard | External API call budget exceeded; further calls require human approval.
    seq 18 | 2026-09-21T14:25:22+00:00 | human-operator (approver) | api_call | endpoint="issues.list" params={"repo": "synthetic-repo", "page": 6} | approved | policy approval-external-rate-guard | Read-only API call needed to finish triage; one-time budget exception granted.

### [MEDIUM] File write outside the sandbox held for approval

- Status: resolved: rejected by a human
- Policy: `approval-write-outside-sandbox`

The builder agent attempted to write a file outside its run sandbox. The write was queued for human approval rather than executing.

Evidence (exact log entries):

    seq 15 | 2026-09-21T14:25:22+00:00 | builder-01 (builder) | write_file | path="/tmp/rogue-patch.diff" content="synthetic patch content
" | queued_pending | policy approval-write-outside-sandbox | File writes outside the run sandbox require human approval.
    seq 20 | 2026-09-21T14:25:22+00:00 | human-operator (approver) | write_file | path="/tmp/rogue-patch.diff" content="synthetic patch content
" | rejected | policy approval-write-outside-sandbox | Writes outside the run sandbox are not permitted, even with approval.

### [MEDIUM] Outbound communication held for human approval

- Status: open: awaiting human review
- Policy: `approval-outbound-sends`

The publisher agent attempted an outbound http_post. Policy requires a human to approve outbound communication, so the action was queued with full context instead of executing.

Evidence (exact log entries):

    seq 16 | 2026-09-21T14:25:22+00:00 | publisher-01 (publisher) | http_post | url="https://hooks.synthetic.local/ci" payload={"run_id": "demo-20260921-142522", "status": "ready"} | queued_pending | policy approval-outbound-sends | Outbound communication requires human approval before it leaves the sandbox.

### [MEDIUM] Outbound communication held for human approval

- Status: resolved: approved by a human and executed
- Policy: `approval-outbound-sends`

The publisher agent attempted an outbound send_email. Policy requires a human to approve outbound communication, so the action was queued with full context instead of executing.

Evidence (exact log entries):

    seq 17 | 2026-09-21T14:25:22+00:00 | publisher-01 (publisher) | send_email | to="maintainer@synthetic.local" subject="Fix for issue #42 ready for review" body="Synthetic outreach email body." | queued_pending | policy approval-outbound-sends | Outbound communication requires human approval before it leaves the sandbox.
    seq 19 | 2026-09-21T14:25:22+00:00 | human-operator (approver) | send_email | to="maintainer@synthetic.local" subject="Fix for issue #42 ready for review" body="Synthetic outreach email body." | approved | policy approval-outbound-sends | Email content reviewed; recipient is synthetic. Approved.

### [LOW] Audit trail integrity verified

- Status: verified
- Policy: `n/a (log integrity)`

The run's action log is hash-chained: each entry commits to the hash of the previous entry. Replaying the chain over 23 entries succeeded. Any tampering with a historical entry would break every later hash.

Evidence (exact log entries):


## Notes

- SYNTHETIC DEMONSTRATION — no real systems were inspected.
- All agent actions, policy decisions, and human approvals in this report come from the run's tamper-evident log; entry sequence numbers above cite the exact records.
