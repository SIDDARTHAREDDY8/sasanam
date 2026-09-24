# Release Approval / Licensing Primitive — Spec

## Problem Statement

The safeguard benchmark grades the governance layer, but nothing governs
the act of SHIPPING: anyone holding the repo can mint a release bundle
and ship it with no ceremony — no recorded evidence of what was
reviewed, no binding between the shipped bits and the evaluation
evidence, and no human sign-off. A release that bypassed the safeguard
benchmark, or whose code changed after the evaluation ran, is
indistinguishable from a properly reviewed one.

## Solution

A pre-release approval (licensing) primitive that turns "ship this
release" into a quorum-gated human ceremony on the EXISTING approval
queue machinery, with digest binding from the release candidate's bits
through the evaluation evidence to the human decision, and a
fail-closed verify path for anyone who must answer "was this release
actually approved?".

## User Stories

1. As a release manager, I want a release candidate to be identified by
   a single digest that binds the code tree, the eval results, and the
   safeguard assessment report, so that any bit flip in any of the
   three changes the release's identity.
2. As a release manager, I want shipping a release to require
   multi-party human approval through the existing approval queue, so
   that one compromised or careless human cannot ship alone.
3. As a governance auditor, I want the approval decision chained into
   the hash-chained audit log with the release digest bound in, so
   that the release decision is as tamper-evident as every other
   governance event.
4. As a deployment operator, I want a verify path that takes a release
   candidate and answers approved/not-approved by recomputing the
   digest and checking the chained approval, failing closed on any
   mismatch, so that unverified releases cannot be deployed.
5. As a release manager, I want an approval minted for a different
   digest to be refused for my release candidate, so that approvals
   cannot be transplanted across releases.
6. As a release manager, I want a replayed approval from an older
   release to be refused against a changed candidate, so that old
   approvals cannot launder new bits.
7. As a release manager, I want a single approver to be refused when
   the quorum is two, so that the ceremony cannot silently degrade to
   one-party sign-off.
8. As a human voter, I want to cast my vote through the same approval
   queue (and CLI) I already use for tool approvals, so that no new
   identity or voting machinery must be learned.
9. As a governance auditor, I want the quorum snapshot (min approvals,
   eligible principals) MAC-bound to the record at queue time, so that
   a later policy edit cannot shrink the quorum under a live release
   approval.
10. As a release manager, I want the quorum configuration to fail
    closed at install time (e.g. unreachable quorums rejected), so
    that a misconfigured ceremony cannot starve silently.
11. As a deployment operator, I want stale approvals (decided beyond
    the TTL) to be refused at verify time, so that an old ceremony
    cannot authorize a present-day ship.
12. As a security reviewer, I want a forged approval record — one that
    never passed the queue — to fail the keyed integrity check, so
    that hand-written "approvals" are refused.
13. As the product owner, I want the honest residual documented (this
    governs OUR release ceremony; it is not DRM against someone
    copying the code and shipping it elsewhere), so that nobody
    mistakes ceremony for copy-prevention.

## Implementation Decisions

- The primitive lives in a NEW module in the governance layer
  (`release_approval`); it consumes the existing approval queue
  read-only and never rewrites it. Modules owned by other lanes are
  untouched.
- Digest scheme: canonical, deterministic hashing. The code-tree digest
  walks the candidate tree sorted by relative path, hashing each file's
  bytes; the eval-results and SAR digests are over file bytes; the
  release digest is a domain-separated SHA-256 over the three
  sub-digests. Every digest is lowercase hex. Any bit flip in any input
  changes the release digest.
- The release approval is queued as a `ship_release` action through
  the existing approval queue with the release digest and sub-digests
  in the redacted args (args are MAC-bound by the queue, so a post-queue
  digest swap breaks the record digest and is refused).
- Quorum is enforced by the EXISTING quorum machinery: the primitive
  installs a quorum config with `min_approvals >= 2` (refusing to
  install anything weaker) before queueing, so the record opens in
  `decision_mode="quorum"` with the snapshot MAC-bound. Single-party
  `decide()` is refused by the queue on quorum records; finalization
  happens only through authenticated per-principal votes. The quorum
  snapshot rides the queue's keyed record digest, so a config edit
  cannot shrink the quorum under a live approval.
- When the M-th approval vote finalizes the record, the primitive
  appends an explicit `release_approval_granted` event to the
  hash-chained audit log, binding the release digest, the approval id,
  and the voter principals. The queue's own `quorum_finalized` /
  `approval_decision` events provide the underlying decision trail.
- The verify path: given a release candidate (code tree + eval results
  + SAR) and a queue (or run dir), it (1) recomputes the release digest
  and compares it to the digest bound in the approved record; (2)
  verifies the record's keyed integrity digest (forged records fail);
  (3) requires the record status `approved`, `decision_mode ==
  "quorum"`, and at least `min_approvals` distinct voter principals
  from the MACed snapshot; (4) requires a matching
  `release_approval_granted` entry in the audit log with the same
  release digest; (5) verifies the audit-log chain tip; (6) refuses
  approvals older than the TTL. Any mismatch → not-approved, fail
  closed.
- The quorum's eligible set must not contain the requester (enforced by
  the queue at queue time); votes are authenticated human identities
  via the existing executor-minted identity path.
- Honest residual, stated in the module docstring, the spec, and the
  battery: this governs OUR release process (ceremony + evidence before
  ship). It is NOT a DRM that stops someone copying the code and
  shipping without the ceremony. Under the public development log key,
  the keyed record MAC is forgeable by anyone who read the docs (the
  same F34 residual as the rest of the approval system); production
  needs a real log key.
- Seams (pre-agreed): the primitive's public functions (digest
  builders, propose/ship/verify, vote recorder) and the existing
  approval-queue seam (queue / cast_vote / decide / set_quorum_config)
  plus the hash-chained audit-log seam (append / chain verification).
  Tests run through the real queue via the existing test harness, not
  mocks.

## Testing Decisions

- Red-first: a break-first battery is written against the UNMODIFIED
  tree, run to show the attacks all succeed (no gate exists), then the
  primitive is implemented and the same battery is re-run to show the
  attacks are held.
- The battery covers exactly: forged approval presented for ship;
  approval for a DIFFERENT digest transplanted onto the candidate;
  replayed approval from an older release; single approver against a
  quorum of 2. Each probe reports BREAK (attack succeeded — bad),
  HELD (attack refused — good), or ERROR.
- A CONTROL probe ships a legitimately quorum-approved release and
  asserts it verifies, proving the gate does not just refuse
  everything.
- Expected values come from independent recomputation (re-hash the
  bytes with plain hashlib in the test), never from the implementation
  under test.
- Durable regression tests live in the repo's test tree at the public
  seams; the battery file carries the deployment-mode line required
  for standalone runs.

## Out of Scope

- DRM / copy-prevention: stopping someone who copies the code and
  ships without the ceremony is explicitly NOT in scope (honest
  residual above).
- Revoking an already-shipped release; key-compromise recovery beyond
  the existing key-rotation machinery; production key custody (owned
  by the key-custody lane).
- Changes to the safeguard benchmark, the sandbox, the egress
  launcher, or the approval queue itself (other lanes own those).
- Ed25519 signing of release digests (a future strengthening; the
  audit-log chain + keyed queue digest is the v1 binding).
- BUILD_LOG.md and FINDINGS.md edits (central owns those).

## Further Notes

- The quorum config's one-deny veto and the queue's separation of
  duties carry over unchanged: a deny vote finalizes rejection, and
  the requester can never vote on its own release.
- Risk scoring will likely tier a `ship_release` record as critical;
  cooling-off applies per the queue's existing policy data — this is
  advisory for the ceremony and does not weaken the quorum gate.
- Auto-approve can never fire on a quorum record: it goes through
  `decide()`, which refuses quorum-collecting records.
- Votes may arrive through the primitive's `record_release_vote`
  wrapper (which chains the explicit `release_approval_granted` entry)
  or through the queue's own surfaces such as the `gov.approve` CLI
  (which chains the queue's native `quorum_finalized` entry); the
  verify path accepts either, since the digest binding in the
  CLI-voted case rides the MAC-verified record's args.
