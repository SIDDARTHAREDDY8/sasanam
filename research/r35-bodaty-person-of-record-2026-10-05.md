# R35 — Bodaty AICtrlNet "person of record" pattern (verified 2026-10-05)

Research ID R35 from the wave-340 prospectus. Question: does Bodaty AICtrlNet
ship a named-human approval pattern we should ADAPT, and does our
`gov/approvals.py` have a named-approver gap?

## 1. License — VERIFIED at the repo

- Repo: `github.com/bodaty/aictrlnet-community` (public, default branch `main`,
  current commit `88bdb360141c5be1192045a3047a464be94d5782`, 362 commits,
  created 2026-01-10).
- GitHub license detection: **MIT License (MIT)**. Root `LICENSE` file read in
  full: standard MIT text, `Copyright (c) 2025 Bodaty`.
- Editions table (README): Community = MIT (this repo); Business/Enterprise =
  Commercial. So the MIT core is legally clean for pattern reads. The
  commercial tiers are off-limits.

## 2. The "person of record" pattern in the MIT repo — marketing, not code

Claim (PRNewswire, ~Aug 2026): a named human gates every consequential action,
landed in timestamped tamper-evident audit records; "the platform never moves
money on its own".

What the MIT repo actually ships (checked 2026-10-05):

- **No `person_of_record` / `PersonOfRecord` entity anywhere** in `src/`.
- **Approval workflows are Community-excluded.** `src/nodes/implementations/
  approval_stub_node.py` raises `RuntimeError("Approval nodes require Business
  Edition or higher")`; the real `ApprovalService` is imported from
  `aictrlnet_business` (commercial, not in the MIT repo) in
  `src/mcp_server/tool_executor.py::_import_approval_service()`.
- **Approver attribution in open code is a plain label.** `_handle_approve_request`
  calls `svc.approve_request(request_id=..., approver_id=user_id, ...)` where
  `user_id` is the session-authenticated user ID — a DB-row label, not a
  cryptographic binding.
- **Audit service has no tamper-evidence machinery.** `src/services/
  runtime_audit_service.py` and `src/schemas/audit.py`: DB rows with Pydantic
  schemas; no hash chain, no HMAC, no signatures found.
- Tier table confirms: "Audit logging and decision tracking (Community); Bias
  detection and monitoring (Business); 5-layer AI Workflow Security Gateway
  (Business/Enterprise)".

**Verdict: WATCH (unchanged) — patterns only.** There is no cryptographic
named-approver primitive in the MIT repo to steal. The real takeaway is the
market-driver angle: CA AB 316 ("the AI acted on its own" is no defense) and
the EU revised Product Liability Directive make "who approved that?" a
first-class buyer query. That belongs in the GTM file, not the product.

## 3. Our named-approver posture (gov/approvals.py, base adaafaef) — no gap

Red-team audit result: the gap R35 feared is absent / already covered.

- **F26 (CLOSED 2026-09-21)** covers the impersonation shape: `break_glass()`
  and `resolve_review()` require an `AgentIdentity` object — caller-supplied
  strings raise `TypeError`; executor-minted identities only
  (`UnmintedIdentityError` otherwise); the identity verifier is write-once.
  Re-verified on base: `tests/test_hardening_r6.py::TestF26BreakGlassIdentity`
  8/8 OK; a `reviewer_identity="bob"` string probe is refused with TypeError.
- **`decided_by` is MAC-bound post-decision (tamper-evident history).**
  Verified: decide with `decided_by="alice"` → `approval_digest_ok` True;
  rewriting the record to `decided_by="mallory"` → `approval_digest_ok` False.
  History cannot be rewritten without breaking the MAC.
- **Issuance model is a documented localhost-grade residual, not a break.**
  CLI `--by` is free text (terminal trust root; any terminal operator can type
  any name). Web uses the fixed label `web/human-operator`
  (`gov/approval_web.py: WEB_DECIDED_BY`) — the session binds one operator
  principal, no SSO/OIDC/mTLS; the console docstring explicitly calls itself a
  localhost tool, not an IAM system. Session-identity self-assertion is
  F50 (MEDIUM, wave-13); "library-layer decided_by remains caller-asserted" is
  a documented residual in the F101/F103 closures and the D1-core notes in
  `gov/approvals.py` (lines ~2938, ~3376, ~3444, ~8495).

**Verdict: NO FINDING filed.** A "person of record" entity bound by a
deployment PKI/OIDC would change the web console from a localhost tool into an
IAM system — that is a production-deployment decision (PrincipalRegistry /
session identity provider), not an independently-reachable product break on
the current tree. Filing F428 would be finding inflation.

## 4. What WOULD be a genuine gap (for future red-teams)

- A web operator's session principal being *spoofable by the client* (form
  field instead of server session) — checked: delegation/vote routes use the
  server-side session principal; decide uses the fixed label. Held.
- A post-decision `decided_by` rewrite passing the MAC — checked: fails the
  digest. Held.
- Break-glass ticket redemption by an unminted identity — covered by F26.
