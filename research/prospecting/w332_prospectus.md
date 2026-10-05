# Wave-332 Industry Prospectus: MCP Auth Hardening, PQC Slot Naming, GPAI Incident Cadence, Supply-Chain Graphs, Rotation Ceremonies, Competitive Watch

**Date:** 2026-10-05 · **Base:** `cef4ad59` (wave-331 merge, footer open none / next F417, pin 2058)
**Method:** primary sources only (spec texts, source code, first-party docs, LICENSE files). Every factual claim carries URL + access date 2026-10-05.
**Standing rule honored (wave-331 lesson):** for EVERY verdict the tree was checked FIRST (`grep -ri gov/`). The w330 prospectus's #1 STEAL duplicated the wave-266 Landlock tier because the tree check was claimed but not run — this prospectus runs it and prints the evidence.

## Prior-prospectus avoidance

Covered before (not repeated here): Landlock/nsjail/gVisor/Bubblewrap/Firecracker (w330 §1; Landlock built wave-331 lane 3); PQC algorithm analysis + reserved-slot proposal (w330 §2 — slot still unbuilt, see §2 below); MCP OAuth gaps #1+#2 as ADAPT items (w330 §3 — sharpened here against the 2026-07-28 spec revision); A2A auth-scheme posture/push-webhook/in-task auth/task scoping/elicitation URL mode/step-up/AP2 (w330 §3); Art. 73/55 incident envelope incl. GPAI template fields, EU SEND, Art. 73(6) freeze, Annex XI/XII (w330 §4 — the GPAI *chapter 9 cadence* delta is new, see §3); TUF/in-toto/Sigstore/ORAS/Harbor (w306–w325); Rekor-pattern witness (w321); offline verifier (w310); dex/SPIFFE/keto/Cedar identity (w318); C2PA provenance (landed: `gov/c2pa_provenance.py`).

---

## 1. MCP authorization spec 2026-07-28 — client hardening is the STEAL

| Target | Verdict |
|---|---|
| RFC 8707 `resource` in authorization + token requests | **STEAL** |
| RFC 9207 `iss` on the authorization-response leg | **STEAL** |
| RFC 9728 Protected Resource Metadata discovery | **STEAL** |
| Token-passthrough prohibition (server side) | **STEAL** |
| Step-up authorization (403 `insufficient_scope` → scope-union → retry-limit) | **ADAPT** (backlog) |

**Tree check (run, not claimed).** `gov/mcp_oauth_binding.py` EXISTS (W245-1): sealed AS binding under HMAC, issuer validated on every *discovery* path, credentials bound per-AS (`mcp-oauth-credential-misbound`), choke point `run_bound_exchange`. `gov/mcp_invocation_authz.py` exists. What is genuinely absent: `grep -niE '"iss"|\bresource\b' gov/mcp_oauth_binding.py` → **zero hits**. The 2026-07-28 MCP authorization spec (https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization, accessed 2026-10-05) tightened exactly these points: client **MUST** include `resource` (RFC 8707) in *both* authorization and token requests; authorization servers **SHOULD** return `iss` and clients **MUST** validate it against the recorded issuer before redeeming the code (RFC 9207) — the mix-up defense; Protected Resource Metadata (RFC 9728) is **mandatory** for servers; **token passthrough is forbidden** ("MCP servers MUST NOT accept any tokens that were not explicitly issued for the MCP server"); client credentials **MUST** be keyed by issuer and never reused across authorization servers; Dynamic Client Registration deprecated in favor of CIMD (SEP-991).

**Why this is a steal, not a duplicate.** Our binding seals the issuer at *discovery* and *exchange* time but never sees the authorization-response leg — a hostile AS can hand the client an honest AS's code without `iss`, and the client redeems it. RFC 9207 closes exactly that leg: the `iss` value is added server-side by the AS, the baseline is the client's own recorded issuer, "no normalization" (spec-2026-07-28 review, harekrishnarai/mcp-security-review). RFC 8707 binds the token to one MCP server (audience pinning), complementing our per-AS credential binding. Both are spec-**MUST**s in the current revision, both absent, both slot into the existing sealed-binding module without new architecture.

**Falsifiable next step:** extend `mcp_oauth_binding.py` with `check_authorization_response(sealed_binding, response_params)` refusing `mcp-oauth-iss-mismatch` when a present `iss` ≠ recorded issuer (and refusing when the AS's metadata advertises `iss` support but the response omits it), plus `resource` injection/validation in the request builders; red-first probes: (a) mix-up response without `iss` → coded refusal; (b) `iss` naming the wrong AS → coded refusal; (c) token request without `resource` → coded refusal; (d) server accepting a token issued for another resource → coded refusal.

**License:** no encumbrance — implementing IETF RFCs (8707, 9207, 9728) and a published protocol profile requires no license; patterns only, no code copied.

---

## 2. Open Quantum Safe (liboqs) — identifier discipline for the reserved PQ slot

| Target | Verdict |
|---|---|
| liboqs algorithm naming + OID registry conventions | **ADAPT** (narrow: naming only) |
| liboqs code / oqs-provider | **SKIP** (C code; violates stdlib-only) |
| Production ML-DSA signing | **SKIP** (unchanged from w330 §2: nowhere to ship, no constant-time Python) |

**Tree check (run, not claimed).** `grep -rniE 'pqc|ml-dsa|ml-kem' gov/evidence/ gov/bundle*.py` → **zero hits**: the evidence envelope has **no reserved PQ slot** — w330 §2's falsifiable next step #1 (format-only reserved slot, Ed25519 authoritative) is still unbuilt. `gov/hybrid_gate.py` has classical/pqc *role* downgrade checks, but no algorithm identifiers anywhere.

**What liboqs contributes.** Not crypto — the *naming table*: `mlkem512/768/1024`, `mldsa44/65/87`, `slhdsa-*` canonical identifiers (open-quantum-safe/oqs-provider `ALGORITHMS.md`, referenced from https://github.com/open-quantum-safe/oqs-provider/blob/main/ALGORITHMS.md, accessed 2026-10-05), plus the hybrid naming convention (`X25519MLKEM768`, renamed `SecP384r1MLKEM1024` June 2025 per draft-kwiatkowski-tls-ecdhe-mlkem-03). The steal is the *registry discipline*: a closed, versioned algorithm-identifier table in the envelope format with "unknown identifier refuses" semantics — the same closed-vocabulary discipline the tree already uses for decision graphs — so that when Sigstore's ML-DSA enums leave "Experimental," the slot activates without a format break.

**Falsifiable next step:** envelope gains `pq_alg_id` (string, closed table: `ed25519` + reserved `mldsa44/65/87`, all PQ values currently refuse `evidence-pq-not-enabled`) and `pq_signature` (bytes, must be empty while disabled); red probes: unknown `pq_alg_id` → coded refusal; non-empty `pq_signature` while disabled → coded refusal; classical path byte-identical.

**License:** **MIT verified from the LICENSE file** (https://raw.githubusercontent.com/open-quantum-safe/liboqs/main/LICENSE.txt, accessed 2026-10-05: "The MIT license … applies to liboqs in general"). No trap — and no code is copied anyway (naming only).

---

## 3. GPAI Code of Practice, Safety & Security ch. 9 — the incident cadence delta

| Target | Verdict |
|---|---|
| Measure 9.2 report content points (1)–(7) as a field checklist | **ADAPT** |
| Measure 9.3 timeline bands (2/5/10/15 d) + 4-week intermediate + 60-day final | **ADAPT** |
| Measure 9.4 five-year retention | **ADAPT** |
| Awareness-includes-reasonable-suspicion | **ADAPT** |

**Tree check (run, not claimed).** `grep -rniE 'measure 9\.[234]|commitment 9|every 4 weeks|60 days|5-year|five-year|intermediate report' gov/*.py` → **zero hits**. `gov/incident_export.py` has Art. 73 tiers (2/10/15 days) and Art. 3(49) definitions, but none of the GPAI-chapter-9 machinery.

**What the Code says (primary: GPAI Code of Practice, July 2025, Safety and Security chapter, Commitment 9; corroborated by the smith-mern/aisecuritysecondbrain transcription of Measures 9.2–9.4 and the dig.watch third-draft text, accessed 2026-10-05).** Measure 9.2 report content: (1) start/end dates, (2) root-cause analysis, (3) chain of events, (4) the model's involvement, (5) patterns from post-market monitoring linked to the incident, (6) resulting harm, (7) responses + recommendations to authorities; unavailable information must be recorded explicitly as unavailable. Measure 9.3 timelines, from *awareness* (which **includes reasonably suspected** model involvement): critical-infrastructure disruption ≤ 2 days; **serious cybersecurity breach (exfiltration, cyberattack) ≤ 5 days** — a class Art. 73 does not name; death ≤ 10 days; serious harm to health/fundamental rights/property/environment ≤ 15 days. **Intermediate report at least every 4 weeks** until resolved; **final report ≤ 60 days after resolution**. Measure 9.4: **retain all documentation ≥ 5 years**. GPAI systemic-risk duties apply since 2 Aug 2025 (Art. 55 live now) — this is build-now, not build-later.

**Why this is the delta over w330 §4.** w330 §4 built the Art. 73/55 envelope case (severity→clock, awareness + causal-link timestamps, template fields). The Code adds: the 5-day cybersecurity band (our threat class), the suspicion-inclusive awareness definition (lowers the timeliness bar we must evidence), the 4-week intermediate cadence (a *reporting* duty, not just an investigation), the 60-day final, and 5-year retention (longitudinal records management — note the reasonsmith gap analysis flags retention as "not observable from a single presence-oriented record," i.e., it must be designed in).

**Falsifiable next step:** `incident_export.py` gains a GPAI-9.x report builder: field checklist (1)–(7) with explicit "unavailable" marking; clock mapping including the 5-day class; intermediate-due-date computation; red probes: (a) report missing point (4) without an unavailable-mark → coded refusal; (b) cybersecurity-class incident with awareness 6 days ago and no initial report → timeliness violation flagged; (c) resolved incident 61 days ago without final report → violation flagged.

**License:** Commission-published regulatory document — public source, no license trap; cite as regulatory authority, not code.

---

## 4. GUAC (guacsec/guac) — SKIP with evidence

| Target | Verdict |
|---|---|
| GUAC graph model / assemblers / policy engine | **SKIP** |

**Tree check (run, not claimed).** `gov/bom_queries.py` implements a **DecisionGraph** with a *closed* node vocabulary (unknown kinds refused at `add_node`), a **FROZEN edge ALLOWLIST** (no mutating API; changes require a new `ALLOWLIST_VERSION` + `allowlist_digest`), and a pinned report-dispatch registry. GUAC (guacsec/guac — "Graph for Understanding Artifact Composition," Google/OpenSSF) ingests SBOMs, SLSA/in-toto attestations, OSV feeds into a graph for blast-radius queries ("certify a builder is compromised, then query affected artifacts" — thehackernews.com 2023-05, sdxcentral analysis, accessed 2026-10-05).

**Why SKIP.** GUAC's open assembler model (ingest anything, query later) is strictly weaker than our closed-vocabulary + frozen-allowlist discipline: our graph cannot silently widen, GUAC's can. The problem GUAC solves — "which decisions/artifacts sit in the blast radius of a compromised component" — is already answered by `bom_queries.py`'s headline queries over a fail-closed graph. There is nothing to steal without downgrading our discipline.

**License:** **Apache-2.0 verified** (https://raw.githubusercontent.com/guacsec/guac/main/LICENSE, accessed 2026-10-05). No trap — irrelevant, since the verdict is SKIP.

---

## 5. Teleport (gravitational/teleport) — WATCH, with a license trap

| Target | Verdict |
|---|---|
| CA rotation ceremony (dual-trust phases) | **WATCH** (pattern already in tree) |
| Node join tokens / short-lived node certs | **WATCH** |

**Tree check (run, not claimed).** `gov/revocation_status.py` already implements the phased rotation ceremony: "keeps old+new anchors during an overlap window, never an atomic swap … old retires only after new is proven live" (`advance_key_rotation(overlap_window_seconds)`). `gov/agent_identity.py` has dex-adapted short-lived identity tokens + refresh rotation. Teleport's documented CA rotation (docs: `zero-trust-access/management/security/ca-rotation`, goteleport.com) is the same dual-trust phase machine: introduce new CA → distribute trust bundle → rotate credentials → retire old. Nothing to steal without duplicating the tree.

**WATCH condition:** Teleport's rotation *state machine with rollback* (what happens when a phase fails mid-rotation across a fleet) — our ceremony is single-host; if multi-host agent fleets become a deployment shape, revisit.

**LICENSE TRAP — AGPL-3.0.** The Teleport LICENSE file is the **GNU Affero General Public License v3** (https://raw.githubusercontent.com/gravitational/teleport/master/LICENSE, accessed 2026-10-05 — NOT Apache-2.0 as commonly assumed). **Do not copy, vendor, or closely paraphrase Teleport code**; patterns only, and even pattern-adaptation must be clean-room prose. This is the Fleet-class trap the standing license rule exists for.

---

## 6. Competitive WATCH — Bernstein (agent-governance frameworks)

| Target | Verdict |
|---|---|
| sipyourdrink-ltd/bernstein (+ forks: amirf194, ecgang, abu-pixel, sanjays2402) | **WATCH** (direct competitor) |
| Attestix (DID agent identity, 47 MCP tools) | **WATCH** (competitor) |

**What it is (primary: repo READMEs/CLAUDE.md, accessed 2026-10-05).** Bernstein (https://bernstein.run, https://github.com/sipyourdrink-ltd/bernstein): "the open-source AI Agents Governance & Orchestration framework — write the rules declaratively, Bernstein enforces them and produces the verifiable, replayable record." Apache-2.0. Headline mechanics: deterministic scheduler (no LLM in the coordination loop), always-on Merkle-chained replay journal + lineage spine, opt-in HMAC-SHA256 audit chain, `replay --verify` surfacing non-determinism as hash mismatch at the exact step, air-gap install profile, 40–52 CLI agent adapters, MCP server. One fork documents **verifiable governance**: every access/budget check is a signed record `{subject, action, verdict, inputs_hash, journal_entry_hash}`, and `governance verify` **re-resolves and re-projects every recorded decision** from bindings + ledger — a tampered verdict fails.

**Honest competitive read.** Several headline features overlap Sasanam's existing capabilities (HMAC audit chain, offline verification, replayable record, air-gap posture). Bernstein's edge is *orchestration-first* (it schedules the agents; we govern the seams) and breadth of CLI-agent adapters. The one pattern worth tracking: **offline re-projection of governance decisions** — re-executing recorded decisions from the presented bindings and ledger rather than merely verifying signatures. Tree check: `gov/arap.py` has key+body decision replay ("the same key + identical body replays the original decision"); whether our *offline verifier* re-projects approval/budget decisions from the bundle (Bernstein's `governance verify` shape) is unconfirmed — treat as an open question for a future lane, not a gap.

Attestix (from GitHub topics/attestation): "Attestation Infrastructure for AI Agents. DID-based agent identity, W3C Verifiable Credentials, EU AI Act compliance layer, delegation chains, and reputation scoring. 47 MCP tools across 9 modules." (accessed 2026-10-05). Direct overlap with our VC bundle + trust federation + incident export; watch for their EU AI Act compliance-layer field choices.

**License:** Apache-2.0 per repo claims. No trap flagged, but verify from the LICENSE file before adapting anything.

---

## Prioritized build list (strongest first)

1. **MCP client OAuth hardening** — RFC 8707 `resource` + RFC 9207 response-leg `iss` + RFC 9728 PRM discovery in `mcp_oauth_binding.py` (§1). Spec-MUSTs, crisp probes, slots into the existing sealed-binding module.
2. **GPAI chapter-9 incident cadence** — Measure 9.2 field checklist, 5-day cybersecurity band, 4-week intermediate, 60-day final, 5-year retention in `incident_export.py` (§3). Live law (Art. 55 since Aug 2025).
3. **Reserved PQ envelope slot** — closed `pq_alg_id` table (liboqs naming), Ed25519 authoritative, PQ values refuse `evidence-pq-not-enabled` (§2). Format-only.
4. **WATCH:** Teleport rotation rollback state machine (multi-host trigger); Bernstein offline governance re-projection (confirm tree status first); Sigstore ML-DSA enums leaving Experimental; final Art. 73 guidance.

## Explicit non-steals (tree-checked)

- Decision-graph supply-chain queries (GUAC's problem): `gov/bom_queries.py` closed-vocabulary DecisionGraph — SKIP (§4).
- Anchor/identity rotation ceremonies (Teleport's problem): `gov/revocation_status.py` dual-trust overlap + `gov/agent_identity.py` short-lived tokens — WATCH only (§5).
- Sealed MCP OAuth issuer binding (GHSA-qx49 shape): `gov/mcp_oauth_binding.py` — this prospectus steals only its *gaps* (§1).
- C2PA provenance, Rekor-pattern witness, admission policy, VC bundle, trust federation — all present; not re-prospected.

## Open questions

- Does the offline verifier re-project approval/budget decisions from the bundle (Bernstein's `governance verify` shape), or verify signatures only? (`gov/arap.py` has replay; the verifier's coverage is unconfirmed.)
- `gov/evidence/crosswalk.py` Annex XI/XII coverage — still unconfirmed (carried from w330).
- MCP spec repo LICENSE for the authorization text (implementation targets IETF RFCs — no encumbrance — but confirm before quoting spec prose).
- Final Art. 73 guidance publication date — re-run §3 gap analysis when it lands.
