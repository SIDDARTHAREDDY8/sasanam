# EU AI Act Articles 50 & 73 — primary-source notes (2026-09-27)

Research for `gov/incident_export.py`. Claims below are checked against
the EUR-Lex consolidated text of Regulation (EU) 2024/1689
(consolidated version 02024R1689-20260727, via eur-lex.europa.eu) and
corroborating secondary summaries. Not legal advice. No regulator has
accepted the incident-report format built from these notes.

## Article 73 — Reporting of serious incidents

- **73(1)**: Providers of high-risk AI systems placed on the Union
  market shall report any serious incident to the market surveillance
  authorities of the Member States where the incident occurred.
- **73(2) — general rule**: report "immediately after the provider has
  established a causal link between the AI system and the serious
  incident or the reasonable likelihood of such a link, and, in any
  event, **not later than 15 days** after the provider or, where
  applicable, the deployer, becomes aware of the serious incident."
  The period takes account of the severity.
- **73(3) — 2-day tier, TWO independent triggers**: "in the event of a
  **widespread infringement** or a serious incident as defined in
  **Article 3, point (49)(b)**, the report shall be provided
  immediately, and **not later than two days**" after awareness.
  Widespread infringement is defined separately (Art. 3(61)) — it is
  NOT a fifth letter of Art. 3(49) and not a modifier of 3(49)(c).
- **73(4) — death tier**: "in the event of the death of a person, the
  report shall be provided immediately after the provider or the
  deployer has established, or as soon as it suspects, a causal
  relationship … but **not later than 10 days**" after awareness.
  Note: the 10-day clock is death-only; 3(49)(a) also covers serious
  health harm, which falls under the general 15-day rule.
- **73(5)**: an incomplete initial report followed by a complete
  report is allowed where necessary for timely reporting.
- **73(6)**: immediately after awareness the provider performs the
  necessary investigations (risk assessment, corrective action),
  cooperates with authorities, and **must not alter the system in a
  way affecting evaluation** before informing authorities.
- **73(8)**: the market surveillance authority acts within seven days
  of receiving the notification (authority-side clock, not the
  provider deadline).

There is NO single 72-hour deadline — that figure is GDPR Art. 33
(personal-data breach), a separate regime.

## Article 3(49) — "serious incident" definition

Any incident or malfunctioning of an AI system that directly or
indirectly leads to:
- **(a)** the death of a person or serious harm to a person's health;
- **(b)** a serious and irreversible disruption of the management and
  operation of critical infrastructure;
- **(c)** the infringement of obligations under Union law intended to
  protect fundamental rights;
- **(d)** serious harm to property or the environment.

## Article 50 — Transparency obligations (in force since 2026-08-02)

The Digital AI Omnibus deferred Annex III high-risk obligations but
NOT Article 50. The duties attach to what the system does, not to a
risk tier.

- **50(1)**: providers of AI systems intended to interact directly
  with natural persons must ensure the persons are informed they are
  interacting with an AI system (unless obvious). For AI agents: the
  agent must disclose its artificial nature AND the identity of the
  natural/legal person on whose behalf it acts.
- **50(2)**: providers of systems generating synthetic audio, image,
  video or text must mark outputs in a machine-readable format so
  they are detectable as artificially generated/manipulated —
  "effective, interoperable, robust and reliable as far as technically
  feasible". Systems placed on the market before 2026-08-02 got a
  grace period to 2026-12-02 for the technical marking only.
- **50(3)**: deployers inform persons exposed to emotion-recognition
  or biometric-categorisation systems.
- **50(4)**: deployers disclose deepfakes and AI-generated text
  published as news on matters of public interest (carve-outs:
  artistic/satirical/fictional works; text under human editorial
  responsibility).
- The Commission adopted final Guidelines on Transparency Obligations
  on 2026-07-20. Penalties for Art. 50 breaches: up to €15M or 3% of
  worldwide annual turnover.
- Deployers must not remove or alter provider-embedded watermarks.

## Commission's Art. 73 reporting template (draft guidance)

Five-section shape (via secondary summaries; the draft template
itself was not fetched as a primary source):
1. Administrative information — notifying party/contact, discovery
   and estimated occurrence times, affected Member States.
2. AI system data — name/description/version, Annex III category,
   registration/reference info, sectoral-law coverage.
3. Incident description — factual narrative, serious-outcome type,
   affected persons, geographic scope.
4. Preliminary analysis — causal-link assessment, immediate
   corrective action, investigation status, parallel reporting duties.
5. Additional comments.

## Mapping into gov/incident_export.py

- `incident.reporter` ← 73 §1 (notifying party, contact, authority,
  awareness_ts, member_states).
- `incident.system` ← 73 §2 (name/version/Annex III/EU DB
  registration) + policy version+digest in force at the incident
  (evidence for the 73(6) no-alteration duty).
- `incident.incident` + `incident.harm` ← 73 §3 (onset/detection/
  containment timestamps, narrative, Art. 3(49) outcome fields,
  suggested deadline tier from 73(2)-(4)).
- `incident.causation` + `incident.containment` ← 73 §4 (causal-link
  assessment, root-cause pointers, corrective measures,
  investigation status) and 73(6) investigation duty.
- `incident.followup` ← 73 §5 (supplementary reporting).
- `incident.evidence` — the machine-verifiable layer the template
  does not define: redacted timeline, deterministic causal chain,
  completeness claim, redaction report, anchor receipt.
- Art. 50 provenance the engine can attest: agent identity
  (`identity_minted`: agent_id/role/principal — the "on whose behalf"
  disclosure), entry-signer key, per-entry signatures. The module is
  not an Art. 50 compliance claim.

## Sources

- EUR-Lex consolidated text 02024R1689-20260727:
  https://eur-lex.europa.eu/eli/reg/2024/1689/2026-07-27/eng
- Article 73 mirror with paragraph text:
  https://github.com/adoptintelligence-ai/actlas/blob/HEAD/EU-AI-Act-Vault/01%20Articles/Article%2073.md
- Art. 73 deadline tiers + Art. 3(49) classification mapping:
  https://github.com/moltycel/moltrust-api/blob/HEAD/docs/spec-fakten/eu-ai-act-2024-1689.md
- Art. 73(3) two-trigger analysis (widespread ≠ 3(49)):
  https://github.com/chandlercvaughn/acef/blob/HEAD/planning/ACEF-RFC-0002-ai-incident-reporting-profile.md
- OECD "Defining AI incidents and related terms" (Art. 3(49) text):
  https://oecd-ai.case-api.buddyweb.fr/storage//policy-initiatives/Jul2025/fu_c5wcd3wanzkbpp9.pdf
- Art. 50 duties, applicability dates, omnibus deferral:
  https://github.com/fdidonato/moralstack/blob/HEAD/docs/eu_ai_act_landscape.md
- Art. 50 paragraph mapping + machine-readable marking practice:
  https://github.com/open-coder-ai/chock-catalog/blob/HEAD/compliance/eu-ai-act-transparency/references/article-50.md
