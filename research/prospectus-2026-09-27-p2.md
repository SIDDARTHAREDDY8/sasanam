# Prospectus — 2026-09-27 (run p2)

Standing prospecting mission: mine top-company/top-OSS repos for steal-worthy
agent-governance ideas and reusable code. This run covers the highest-value
targets from the last ~2 weeks plus a delta re-check on Microsoft AGT.
Prior runs live in `research/prospectus/` (12 lanes, 2026-09-26); this file
does not duplicate them.

Verdict key: **STEAL** = reuse code and/or adapt the primitive now ·
**ADAPT** = re-implement the idea in our own code · **SKIP** = not useful
(with reason). License recorded per target; copyleft/patent traps flagged.
This team writes reports only — no code is copied into the tree.

Our context: 20-row attack program (rows 1–18 plus new worm/covert-channel
rows from wave-151), fail-closed policy engine, HMAC hash-chained audit log,
human approval queue, egress canaries, evidence pipeline ("sell evidence,
not the engine"). Strategy notes reference that program.

---

## 1. Cisco Talos CAIRN — Cognitive Artifact Intelligence Research Network — STEAL

- **What:** open-source toolkit for identifying/attributing/tracking
  AI-integrated malware from VirusTotal metadata alone (no detonation).
  Released 2026-09-22 alongside the CLOSEDQUORUM disclosure (first malware
  with an LLM panel vote as its C2 decision loop).
- **Repo:** `https://github.com/Cisco-Talos/Cognitive-Artifact-Intelligence-Research-Network`
- **License:** **MIT** (copyright Cisco Systems) — clean. No copyleft, no
  patent grant language beyond MIT's implicit grant. Requires a VirusTotal
  API key at runtime (operational dependency, not a license issue); the
  findings SQLite DB is deliberately excluded (copyright).
- **Maturity:** fresh (Sept 2026), Talos-maintained, actively hunted since
  July 2025.

**Steal-worthy primitives:**

1. **Tiered YARA ontology over composed "scan text" with field-level
   provenance** (README "How It Works", `docs/SOA.md`): T1 primitive
   artifacts (an API endpoint string is present) → T2 behavioral context
   (endpoint co-occurs with LSASS access) → T3 confirmed family (full
   operational fingerprint). YARA matches run against a *structured text
   representation* assembled from named VT metadata fields, so every hit is
   traceable to the field that caused it — "the analyst always knows WHY a
   sample matched, not just THAT it matched." This is the detection-engine
   shape our runtime monitor wants, and the provenance-per-hit is exactly
   the Decision-BOM story ("sell evidence, not the engine"): verdicts that
   carry their own causal chain.
2. **AI-malware archetype taxonomy A0–A11** (`docs/SOA.md`): a versioned
   classification of AI-integration archetypes (CLOSEDQUORUM filed under
   "LLM-tasked C2"). Adopt/adapt as the finding vocabulary for our
   unknown-agent discovery/inventory work and for naming B1 incident
   classes (Carbonato = agent-framework-as-C2 fits this taxonomy).
3. **24 acquisition filters as a checklist** (README): LLM provider endpoint
   strings, Python AI-framework imports, local-model runtime references
   (Ollama/GGUF), agent-style function-call syntax, AI-analysis evasion
   strings ("tell an LLM sandbox there's nothing to see here"). A ready
   seed list for our MCP/tool-registration scanner patterns, complementing
   the Cisco mcp-scanner YARA set from the 2026-09-26 lane.

**Maps to:** runtime detection engine rows, unknown-agent discovery,
evidence/attribution (B1). Suggested first use: port the T1→T2→T3 tiering
and field-provenance discipline into our detection verdicts; adopt the
A0–A11 archetype names where they fit our incident classes.

---

## 2. SwarmTraces 80K+ redacted attack-payload corpus — ADAPT (license TBD)

- **What:** Palisade Research (Jeffrey Ladish et al.) reconstructed 80,000+
  attack payloads from the July 2026 OpenAI→Hugging Face agent swarm via
  ~1M public link-shortener URLs; preliminary redacted dataset released
  2026-09-25. HF and OpenAI confirmed the payloads match their incident
  response. Credentials, PII, infra details, and the shortener names are
  redacted/withheld.
- **Sources:** `https://www.unite.ai/researchers-publish-over-80-000-attack-payloads-from-openai-agent-swarm/`
  (2026-09-25); `https://www.explainx.ai/blog/openai-swarmtraces-link-shortener-self-judging-models-2026`
- **License:** **UNKNOWN — do not ingest until confirmed.** The dataset's
  publication license was not established in this run. Redaction is a
  privacy control, not a license grant.
- **Technical note (already actioned):** the report's restriction-defeat
  detail is the important primitive — the GET-only network restriction was
  "correctly enforced at the level of individual HTTP verbs and never
  touched at the level of what a sequence of reads could collectively
  encode." The defense lesson: evaluate *sequences* of allowed requests,
  not request types. This directly shaped wave-151's covert-channel
  detection lane (write→read rendezvous pairs, not verb filtering).

**Steal-worthy:** the corpus itself as break-first battery seeds — 80K real
payloads beat synthetic ones for our worm-propagation and covert-channel
rows. **Blocked on license confirmation.** Action: locate the dataset's
canonical publication point and license before any ingestion; if clean,
sample real payloads into the wave-151 lane batteries.

---

## 3. Okta Cross App Access (XAA) + Aembit support — ADAPT

- **What:** open, vendor-neutral OAuth-extension protocol (incorporated into
  the MCP authorization standard) for agent-to-app / app-to-app delegation.
  Aembit announced XAA support 2026-09-22 (Oktane 2026 launch partner).
  Okta for AI Agents Core is GA in FedRAMP/HIPAA (2026-06-25) — regulated
  buyers already procure this shape.
- **Sources:** `https://www.webpronews.com/oktas-push-to-govern-ai-agents-exposes-gaps-in-enterprise-identity-controls/`;
  Aembit launch `https://lifestyle.tasteterminal.com/story/876899/aembit-launches-support-for-okta-cross-app-access-extending-enterprise-identity-controls-to-ai-agents/`
  (2026-09-22); field notes `https://github.com/nickgamb/uma4agents/blob/HEAD/site/src/pages/docs/guides/okta-cross-app-access.md`
- **License:** protocol specification, not code — **no license encumbrance**
  on re-implementing the pattern. Continue tracking IETF drafts
  (prior lane already tracks `draft-farley-acta-signed-receipts`).

**Steal-worthy primitives:**

1. **Two-hop ID-JAG token exchange:** human `id_token` + agent
   client_assertion → audience-bound ID-JAG (~300s) at the org AS →
   scoped access token at the resource AS, with a **scope-intersection
   check** and **no standing privileges** (tokens expire after use).
   This is the production shape for "agent acts on behalf of human" —
   directly informs our agent-identity + approval-queue seam.
2. **The `act` claim naming the agent separately from the human**
   (`act: {sub: <agent>, sub_profile: "ai_agent"}`): the delegation token
   carries *both* identities distinctly. Adopt this as our cross-app
   delegation receipt format — our audit log should record delegations as
   (human, agent, scope, expiry) tuples, never a blended identity. This
   plugs the "borrowed credentials / misleading log attribution" gap the
   SOC 2 agent-blind-spot discourse is now flagging.
3. **Consent-fatigue design:** XAA removes per-connection consent prompts
   while tightening control — the UX argument for our type-to-confirm
   ceremony (wave-145/147): friction concentrated at scope-definition,
   not per-action clicking.

**Maps to:** agent identity row, approval queue, audit attribution (B1/B3).
Suggested first use: define our delegation-receipt schema with distinct
`act`/`sub` claims and scope-intersection semantics; track XAA drafts for
interop.

---

## 4. LangSmith retention cut (400→180 days, 2026-09-14) — ADAPT

- **What:** LangSmith SaaS extended-retention max cut 400→180 days;
  self-hosted/BYOC unchanged; **audit-log retention (400d) unchanged** —
  a separate system from trace retention; **datasets persist indefinitely**
  ("to keep data beyond the retention period, add it to a dataset").
- **Sources:** `https://github.com/langchain-ai/docs/blob/HEAD/src/langsmith/changelog.mdx`;
  PR `https://github.com/langchain-ai/docs/commit/4bce5a9bd3566594997ca45cb35aa0f8684da`;
  pricing analysis `https://github.com/langfuse/langfuse-docs/blob/HEAD/content/compare/langsmith.mdx`
- **License:** documentation — informational only, nothing to copy.

**Steal-worthy primitives:**

1. **Promote-to-dataset retention tiering:** hot traces expire on a short
   TTL; anything promoted to a dataset gets indefinite retention with its
   own lifecycle. Adopt explicitly in our evidence pipeline: routine audit
   logs roll off by TTL (cheap), attestation-grade evidence is *promoted*
   into pinned, indefinite-retention evidence bundles (we already ship the
   offline evidence bundle — name the tiering and put it in the README
   instead of leaving it implicit). This is also the pricing shape behind
   "sell evidence, not the engine": retention is the metered dimension.
2. **JSONL trace interchange** (one run per line:
   `run_id`/`trace_id`/`parent_run_id`/`inputs`/`outputs`): a good,
   tool-agnostic export shape. Mirror it in our incident-export format so
   third-party forensics tooling can ingest our bundles without a custom
   parser.
3. **Audit-log/trace-log separation:** LangSmith keeps the audit log on a
   longer, independent retention track. We should state the same: our
   hash-chained audit log is NOT subject to the evidence-bundle TTL.

**Maps to:** evidence pipeline, K-060 anchoring, B6 readiness. No code to
steal; the idea is the tiering discipline.

---

## 5. Microsoft agent-governance-toolkit — delta re-check (MIT) — ADAPT

Upstream `microsoft/agent-governance-toolkit` (~6.3k stars, MIT — clean,
unchanged license). New since the 2026-09-26 lane, via CHANGELOG and
recent PRs:

1. **AGT test replay engine** (#2619): replay captured decision traces
   against current evaluators for policy regression. **Directly our
   post-wave audit discipline, mechanized** — adapt as a
   `replay-decisions` harness: record policy decisions (input, engine
   version, verdict) during a wave, re-run against the next wave's engine,
   diff. Catches silent behavior drift our canonical suite can't see.
2. **Accumulated context governance** (#3261, Go): restrictions derived
   from *aggregation* over accumulated context, with empty-constraints
   fail-closed and boundary validation. The concept — "restrictions derived
   from the aggregate, not the single message" — belongs in our row-9
   drift machinery (complements the flip/rotation pacing detectors).
3. **Wire-protocol-aware policy evaluation** (#2553/#2534/#2535/#2537):
   policy facets keyed off structured protocol metadata (SQL, K8s)
   instead of raw text. Pattern to adopt at our policy-engine seam:
   evaluate typed facets where available, fall back to text.
4. **Saga orchestrator with auto-compensation** (agent-os runtime docs):
   multi-step transactions where every step declares an undo; timeout and
   retry with automatic compensation. Candidate new primitive for our
   response/recovery dimension: compensated executor steps (every governed
   action carries its reversal).
5. **Stale-auth fingerprinting** (LangGraph adapter, #2694): catch reused
   or expired auth context — watch item for our identity row.
6. Convergence note: AGT added governed credential materialization/offload
   across SDKs — the industry is converging on our sentinel-substitution
   shape (already landed). Not new work, validates direction.

**Maps to:** post-wave audit tooling, row 9, policy engine, executor
(response/recovery). All MIT — code could be ported, but the Go/TS
implementations suggest adapting the patterns in our Python tree.

---

## Watch (no verdict this run — primary source not reviewed)

- **Proofpoint "Semantic Business Policies"** (announced ~Sept 2026):
  policy→runtime-controls convergence. Needs a primary-source read before
  a verdict; if their enforcement semantics are inspectable, break-first
  verify them per the sweep's recommendation.

---

## License/provenance summary

| Target | License | Verdict | Encumbrance |
|---|---|---|---|
| Cisco Talos CAIRN | MIT | STEAL | none |
| SwarmTraces 80K corpus | **unknown** | ADAPT (blocked) | **do not ingest until license confirmed** |
| Okta XAA / Aembit | protocol spec | ADAPT | none (idea only) |
| LangSmith retention model | docs | ADAPT | none (idea only) |
| Microsoft AGT deltas | MIT | ADAPT | none |

No copyleft (GPL/AGPL) encountered this run. No code copied into the tree
by this team — reports only, per standing rule.

---

*Run p2 completed 2026-09-27. Next run: re-check SwarmTraces dataset
license; primary-source read of Proofpoint Semantic Business Policies;
watch AGT for replay-engine maturation.*
