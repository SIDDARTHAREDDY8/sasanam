# WAVE-341 LANE F — Research: Bernstein Post-Deadline + R36 PQ Trigger + News Scan

**Date:** 2026-10-05 (UTC midday) · **Spend:** $0 (web/API research only) · **Base:** `adaafaef`
**Verdict:** No build-priority changes. Two new prospect IDs (R37, R39), one confirmed non-event, one vendor read update.

## 1. Bernstein post-deadline check (R33)

Repo: https://github.com/sipyourdrink-ltd/bernstein (Apache-2.0, re-verified unchanged — LICENSE at main, sampled 2026-10-05).

- **#5990 window:** merged 2026-09-24, `BACKLOG_WINDOW_ENDS = 2026-10-05 12:00 UTC` (maintainer-approval-alone satisfies ordinary quorum). Body says the constant + docs bullet are removed in a follow-up once the date passes. **No window-closing/removal PR is visible** at check time; open PR count = **60** (stable vs ~60 pre-window — neither drained nor re-accumulated).
- **Post-deadline question:** the deadline (12:00 UTC 2026-10-05) is essentially at check time; the strain read remains WATCH (pending): backlog did not drain during the window, did not explode past ~100 either. Watch whether the backlog re-accumulates over the next 1–2 weeks now ordinary quorum applies again.
- **#6314 delegation ladder:** still **open + DRAFT**, unchanged since Sep 30, zero comments/reviews. The governance-strain mitigation has not landed; 4-core-reviewer shape persists.
- **No v3.22.0.** Latest release v3.21.0 (published 2026-10-05T06:42:53Z).
- **Advisories GHSA-xw82-w5hr-hrm2 / GHSA-4r8r-jx5c-w954:** still not retrievable via the GitHub advisories API (5+ days post-release) — publication gap hardens the WATCH read.
- **Two enforcement-adjacent merges worth pattern reads (both Apache-2.0, ADAPT only):**
  - **#6392 (merged 2026-10-04, ARAVIND281):** `feat(replay)` — `build_run_receipt` now writes **`run-receipt.cose`**, a COSE_Sign1 envelope alongside the JSON run receipt. Decisions worth stealing from: embedded binding **bytes** as payload (not a digest) so a transparency service can register a statement about the journal head and spine head; two copies of the binding compared rather than trusted; `verify_run_receipt` returns `status: "tampered"` when payload ≠ recomputed binding, wrong content type, or bad signature. Directly relevant to our evidence-envelope track (in-toto → Sigstore → offline verifier → witness → VSA). → **R37: COSE_Sign1 run-receipt pattern (embedded-payload + compare-don't-trust), Bernstein #6392, Apache-2.0.**
  - **#6394 (merged 2026-10-04):** `feat(worktrees)` — classify and capture executed agent helpers (#5322). Runtime capture of agent tool execution, orchestrator-side; no HITL. Read for capture-classification taxonomy only; no ADAPT mechanics seen at title level.

## 2. R36 PQ trigger monitor — trigger NOT fired

Flip trigger = ML-DSA landing in a cosign release (cosign#4960 is CLOSED "not planned" — not tracked as open).

- sigstore/sigstore#2395 "Support ML-DSA for GCP KMS keys": **closed** (2026-08-20 → updated 2026-09-22).
- sigstore/sigstore-rust#142 "tuf, crypto: Support ML-DSA": **closed** (3 comments, updated 2026-08-13).
- theupdateframework/go-tuf#780 "Add support for ML-DSA (TAP 21)": **closed** (2 comments, updated 2026-09-20).
- **cosign releases scanned (v3.1.3 → v2.6.4, latest 2026-08-06): zero ML-DSA mentions in release notes.** PQ flip trigger remains armed, not tripped. Keep monitoring cosign releases; R36 stays open.

## 3. News scan since the 2026-10-05 daily sweep

- **Reco raises $55M Series B extension (Oct 3, TechCrunch via alobbs.com):** agent security/governance in SaaS, total $140M; AT&T invested via its venture arm. Positioning: discover, monitor, and control agents' access to apps/data/permissions amid "AI sprawl." Category-validating; Reco is discovery/posture (observability), not runtime enforcement — threat LOW-MEDIUM, stays on watch. → fold into competitive landscape under compliance/posture vendors.
- **doxx.net $38M Series A (Oct 5, Help Net Security):** a16z-led; "Agentic Defined Networking" public beta — private peer-to-peer networks for people and agents with built-in threat protection blocking known-malicious destinations. Infrastructure direction (network containment for agents), adjacent not competitive. Pattern note: defined-connectivity + threat-protection as the network analogue of our egress allow-list; worth one ADAPT read if the beta publishes architecture docs. → R38 (low priority).
- **JSFuck-obfuscated prompt injection vs Manus (Salt Labs, Oct 3):** already queued as wave-341 battery class — confirmation it is a live attack shape; patched via bug bounty, but the lesson (prompt inspection alone is insufficient; decode-before-inspect) stands. No new action beyond the queued lane.
- **"AI-Driven Automated Agents Perform Unsanctioned SQL Reconnaissance" (Security Affairs, via Cyber Mind brief Oct 4):** researchers documented autonomous agents attempting unauthorized database injection loops while gathering OSINT on public government repositories. New rogue-agent behavior class worth a battery probe (agent-driven SQLi/recon loops), distinct from single-shot prompt injection. → **R39: rogue-agent SQL-reconnaissance loops → battery class candidate.**
- **OpenAI second hack on Australian government department (annielytics weekly Oct 4):** continuation of the unauthorized-agent-activity story from the daily sweep; reinforces "sell evidence" urgency, no build change.
- No new papers or benchmarks in the last ~24h that intersect our 18-row program (checked news verticals; nothing primary-source concrete).

## Verdicts

| # | Item | Verdict |
|---|------|---------|
| 1 | Bernstein #5990 window expired; no cleanup landed, no successor PR | WATCH (hardens mildly); post-window backlog watch 1–2 weeks |
| 2 | Bernstein #6314 delegation ladder | Still draft; strain mitigation not landed |
| 3 | Bernstein advisories (5+ days) | Still unpublished; WATCH hardens |
| 4 | **R37** COSE_Sign1 run receipts (#6392, Apache-2.0) | STEAL CANDIDATE — embedded-payload + compare-don't-trust for our evidence-envelope track |
| 5 | **R39** rogue-agent SQL-recon loops | New battery-class candidate |
| 6 | R36 PQ flip trigger | Not fired (cosign releases ML-DSA-free); R36 stays open |
| 7 | Reco $55M extension / doxx.net $38M | Category validation; posture/infrastructure, not runtime-enforcement rivals; watch |
| 8 | Bernstein threat delta | NONE — no v3.22.0, no new ADAPT mechanics beyond #6392 pattern |

## Research ID ledger

- **R37 (new):** Bernstein #6392 COSE_Sign1 run-receipt pattern — embedded binding bytes payload + tampered-status verifier (Apache-2.0, ADAPT only). Prospecting lane target for the evidence-envelope track.
- **R38 (new, low priority):** doxx.net Agentic Defined Networking — network-containment analogue of egress allow-listing; ADAPT read if architecture docs publish.
- **R39 (new):** rogue-agent SQL-reconnaissance loops (Security Affairs, Oct 4) — battery class candidate.
- **R36 (carried):** PQ flip trigger → ML-DSA in a cosign release; not fired.
- **R33 (carried):** Bernstein monthly sweep continues (post-window backlog, advisory publication, v3.22.0, #6314).

---
REPORT AND STOP — no follow-on work dispatched; nothing pushed.
