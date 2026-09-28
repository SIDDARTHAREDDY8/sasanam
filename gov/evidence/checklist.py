"""The evidence_checklist contract.

Contract shape (rebuilt from the documented mcp-ai-governance shape; the
upstream keyword->framework mapper and any readiness scoring are
deliberately NOT rebuilt — direction stays mechanism -> controls, and
this module scores nothing):

    evidence_checklist(framework, control_id) -> {
        "control": {"framework", "control_id", "title", "mapping_status",
                    "verification_note"},
        "documents":       [ ... ],   # policies, plans, procedures the auditor asks for
        "records":         [ ... ],   # completed artifacts proving the control operated
        "system_artifacts":[ ... ],   # live/generated exports an auditor can verify
        "interviews":      [ ... ],   # who the auditor will want to talk to
        "why":             "...",     # what the evidence is meant to prove
        "likely_auditor_questions": [ ... ],
        "common_failure_modes":     [ ... ],
        "sampling_guidance": "...",
    }

Unknown (framework, control_id) pairs raise UnknownControlError — the
checklist never invents a control. Controls cited against ISO/IEC 42001
carry their "unverified" status and the licensed-text caveat through,
so an auditor sees exactly how far the citation can be trusted.
"""

from .crosswalk import CONTROL_REGISTRY, mechanisms_for_control

__all__ = ["UnknownControlError", "evidence_checklist", "checklist_schema_keys"]

checklist_schema_keys = (
    "control",
    "documents",
    "records",
    "system_artifacts",
    "interviews",
    "why",
    "likely_auditor_questions",
    "common_failure_modes",
    "sampling_guidance",
)


class UnknownControlError(KeyError):
    """Raised when a checklist is requested for an unregistered control."""


# Hand-written, per-control auditor checklists. Each class lists what an
# auditor will actually ask for; the mechanism-specific system_artifacts
# are derived from the crosswalk inversion so they stay in sync with the
# shipped code.
#
# Honesty rules for these entries:
#  - "system_artifacts" name export kinds the generator can actually find.
#  - "common_failure_modes" include the product's OWN documented
#    residuals (sell evidence, not the engine — and never oversell it).
#  - nothing here certifies compliance; the "why" states the limit.
_CHECKLISTS = {
    "NIST-AI-RMF-1.0:GOVERN 4.2": {
        "documents": [
            "Risk documentation policy: which AI risks the team must document and how.",
            "Template or schema for the risk/impact records the team produces.",
        ],
        "records": [
            "Completed risk/impact records, including risks accepted (not only mitigated).",
            "Communication records showing impacts shared beyond the team (changelog, advisories).",
        ],
        "why": "To confirm the organization documents the risks its AI technology "
               "creates and communicates them — not merely the risks it chose to fix.",
        "likely_auditor_questions": [
            "Show a risk your team documented but accepted. What changed because of it?",
            "Who outside the engineering team saw these impact records?",
        ],
        "common_failure_modes": [
            "Risk registers that only contain mitigated risks (survivorship documentation).",
            "Approval records that bind the declared target but not the bound canonical "
            "target (F190 residual — fixed in an unpushed lane at checklist time).",
        ],
        "sampling_guidance": "Pull 5 approval records; verify the decided_by identity, risk tier, "
                             "and blast radius are present and MAC-verifiable. Check one record "
                             "where the human refused — refusal must be re-presentable and chained.",
    },
    "NIST-AI-RMF-1.0:GOVERN 4.3": {
        "documents": [
            "Testing policy: what AI testing the organization runs and on what cadence.",
            "Incident identification procedure: how an anomaly becomes an incident.",
            "Information-sharing policy: what is shared, with whom, and when.",
        ],
        "records": [
            "Dated test artifacts (scorecards) for the deployed configuration.",
            "Incident records with tracking/response/recovery trail.",
        ],
        "why": "To confirm testing, incident identification, and sharing are practiced, "
               "repeatable, and evidenced — not ad-hoc.",
        "likely_auditor_questions": [
            "Reproduce the last scorecard from raw logs. What changed since the previous run?",
            "Show the trail from a detected anomaly to a filed incident.",
        ],
        "common_failure_modes": [
            "Scorecards run once and pinned forever; configuration drifted since.",
            "Harness bugs that inflate scores (documented scratch-contamination kept as evidence).",
        ],
        "sampling_guidance": "Take the two most recent AMSB scorecards; confirm grade, defense rate, "
                             "FP rate, and critical-breach list match the versioned corpus run. "
                             "Verify one critical breach has a written residual disposition.",
    },
    "NIST-AI-RMF-1.0:GOVERN 5.1": {
        "documents": [
            "External-feedback policy: how feedback from those external to the "
            "development/deployment team is collected, prioritized, and integrated.",
        ],
        "records": [
            "External feedback records with prioritization and integration disposition.",
        ],
        "why": "To confirm external voices (users, affected communities, downstream "
               "acquirers) can reach the risk process — not just internal teams.",
        "likely_auditor_questions": [
            "Show feedback you received from outside the team. What changed because of it?",
            "How would an affected user report a concern today?",
        ],
        "common_failure_modes": [
            "Feedback channel exists but no record of any feedback ever being acted on.",
            "NOTE: no mechanism in this tree currently evidences this control — "
            "the system_artifacts list below is empty by design, not by omission.",
        ],
        "sampling_guidance": "If external feedback exists, trace one item from receipt through "
                             "prioritization to disposition.",
    },
    "NIST-AI-RMF-1.0:GOVERN 6.1": {
        "documents": [
            "Third-party AI risk policy: how external agents/models are approved for use.",
            "Trust-store management procedure: who may add keys, and how revocation works.",
        ],
        "records": [
            "Verification battery results for the card verifier (28/28 green).",
            "Trust-store change log with approver identities.",
        ],
        "why": "To confirm external agent identity is verified against a managed trust store "
               "before any delegation — not assumed from a self-asserted claim.",
        "likely_auditor_questions": [
            "What happens when a card's kid is unknown? Show the rejection record.",
            "Demonstrate that a fetched jku is never honored (SSRF/key-substitution).",
        ],
        "common_failure_modes": [
            "Trust store additions without dual approval or expiry.",
            "Stale trust data accepted (verifier must reject it; check the battery covers this).",
        ],
        "sampling_guidance": "Sample 3 delegation receipts; verify card_kid binding and "
                             "kid->identity==subject. Check the verifier battery was run on the "
                             "deployed configuration.",
    },
    "NIST-AI-RMF-1.0:MAP 2.2": {
        "documents": [
            "Documented knowledge limits of the AI system and memory tiers.",
            "Policy describing how system output may be utilized and overseen by humans.",
        ],
        "records": [
            "Banner/warning events from the lineage flag (delivery with provenance, not silent).",
            "Tier-computation change log.",
        ],
        "why": "To confirm humans are told the trust limits of what the system shows them — "
               "especially memory content derived from shaped ingestion.",
        "likely_auditor_questions": [
            "Show a delivered paraphrase from shaped ingestion. Was the banner present?",
            "Can the banner be suppressed by configuration? Who may do that?",
        ],
        "common_failure_modes": [
            "Banner fatigue: benign paraphrases delivered with warnings, training humans to ignore them.",
            "Parametric-memory paraphrase carries no lineage (documented residual).",
        ],
        "sampling_guidance": "Pull 10 recent memory recalls; confirm lineage-flagged ones carried the "
                             "banner and unflagged ones did not. Verify the tier ontology was not "
                             "changed to make the flag disappear.",
    },
    "NIST-AI-RMF-1.0:MAP 3.5": {
        "documents": [
            "Human-oversight policy: which actions require human approval and why.",
            "Decision-packet specification: what the human sees before deciding.",
        ],
        "records": [
            "MAC-bound approval records with decided_by identity.",
            "Decision-replay battery results (7/7).",
        ],
        "why": "To confirm human oversight is defined, actually practiced, and itself auditable — "
               "the approver must see the true decision basis.",
        "likely_auditor_questions": [
            "Show what the human saw for this approval. Is the bound canonical target visible?",
            "Replay a past approval decision from the record. Does it match?",
        ],
        "common_failure_modes": [
            "Dishonest ceremony: the packet shows the declared target while execution resolves "
            "a different one (F190 — fixed in an unpushed lane at checklist time).",
            "Approvers rubber-stamping: high approval rate with zero refusals over a long window.",
        ],
        "sampling_guidance": "Sample 5 approvals across risk tiers; verify packet_version, risk score, "
                             "blast radius, and policy citations are bound by the receipt MAC. Check "
                             "refusal records are re-presentable.",
    },
    "NIST-AI-RMF-1.0:MAP 4.1": {
        "documents": [
            "Third-party component risk-mapping approach (data, software, external agents).",
            "Legal risk considerations for third-party components.",
        ],
        "records": [
            "Completed risk maps for third-party components in the deployed system.",
            "A2A card verification battery results as third-party identity evidence.",
        ],
        "why": "To confirm third-party AI technology and legal risks are mapped before deployment, "
               "including runtime identity verification of external agents.",
        "likely_auditor_questions": [
            "Which third-party components touch agent decisions? Show the map.",
            "How was the A2A trust store vetted at onboarding?",
        ],
        "common_failure_modes": [
            "Risk maps written once at procurement and never revisited after component updates.",
            "Self-asserted agent identity accepted without signature verification.",
        ],
        "sampling_guidance": "Verify the risk map covers every third-party component in the "
                             "deployed dependency lock. Spot-check one external agent's card "
                             "verification record.",
    },
    "NIST-AI-RMF-1.0:MAP 4.2": {
        "documents": [
            "Register of internal risk controls per AI system component.",
            "Control ownership and review cadence.",
        ],
        "records": [
            "Memory firewall tier-computation logs.",
            "Delegation receipt samples with scope and identity binding.",
        ],
        "why": "To confirm each risky component (memory, delegation) has an identified, documented "
               "internal control — not just a design intention.",
        "likely_auditor_questions": [
            "For the memory component: which control limits untrusted content? Show it operating.",
            "For delegation: show a receipt where the subject did NOT match the card identity.",
        ],
        "common_failure_modes": [
            "Controls documented in a wiki but not wired into the execution path.",
            "Tier computation bypassed by a second write path (the lane audits for this).",
        ],
        "sampling_guidance": "Confirm every write path routes through the single tier-computation "
                             "site. Sample 3 delegation receipts for scope enforcement.",
    },
    "NIST-AI-RMF-1.0:MEASURE 1.1": {
        "documents": [
            "Measurement approach: which AI risks are measured, with which metrics, and why "
            "these metrics (prioritization rationale).",
        ],
        "records": [
            "Prioritization record linking measured risks back to MAP enumerations.",
        ],
        "why": "To confirm measurement starts with the most significant risks and the choice of "
               "metrics is deliberate, not convenient.",
        "likely_auditor_questions": [
            "Why these scenarios and these severity weights? What did you choose not to measure?",
        ],
        "common_failure_modes": [
            "Measuring what is easy (unit tests) instead of what is significant (adversarial memory).",
        ],
        "sampling_guidance": "Trace 3 top-severity AMSB scenarios back to a MAP-enumerated risk.",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.1": {
        "documents": [
            "TEVV tool documentation: harness design, adapter contract, anti-gaming rules.",
            "Metric definitions: severity weights, FP penalty, grade ceilings, determinism rounds.",
        ],
        "records": [
            "Versioned corpus + versioned scorecards (JSON+TXT pairs).",
        ],
        "why": "To confirm the test sets, metrics, and tools are documented well enough that an "
               "independent party could reproduce the measurement.",
        "likely_auditor_questions": [
            "Reproduce this scorecard. Which corpus version and harness version produced it?",
            "Explain the FP penalty formula and the grade ceilings.",
        ],
        "common_failure_modes": [
            "Undocumented harness changes between scorecard runs.",
            "Shared scratch state contaminating scenario independence (fixed wave-170; kept as evidence).",
        ],
        "sampling_guidance": "Pick a scorecard; re-run the harness on the pinned corpus and confirm "
                             "the grade reproduces within determinism-round tolerance.",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.3": {
        "documents": [
            "Assurance criteria for the deployed setting.",
        ],
        "records": [
            "Quantitative measures (defense rate, FP rate, latency) under deployment-like conditions.",
        ],
        "why": "To confirm assurance claims rest on measured performance in realistic conditions, "
               "documented per measurement.",
        "likely_auditor_questions": [
            "Under what conditions were these measures taken? How do they match production?",
        ],
        "common_failure_modes": [
            "Measures taken in a synthetic setting that does not match deployment tiers/policy.",
        ],
        "sampling_guidance": "Confirm the scorecard's generated_at and corpus version postdate the "
                             "deployed configuration; check latency percentiles against production SLOs.",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.4": {
        "documents": [
            "Production monitoring plan: which behaviors are monitored, thresholds, alerting.",
        ],
        "records": [
            "Egress ledger excerpts per principal; tier-escalation events.",
        ],
        "why": "To confirm the system's behavior in production — especially outbound data movement — "
               "is actually monitored, not just loggable.",
        "likely_auditor_questions": [
            "Show last week's egress for your highest-tier principal. Anything refused? Why?",
        ],
        "common_failure_modes": [
            "Logs exist but nobody reviews them (loggable != monitored).",
            "Content-shape exfiltration: the ledger records tier, not content (documented residual).",
        ],
        "sampling_guidance": "Sample egress entries across tiers; verify refused/flagged egress has a "
                             "chained reason. Check the ledger chain verifies (or note the key-custody "
                             "arrangement for verification).",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.7": {
        "documents": [
            "Security and resilience evaluation approach for the AI system.",
        ],
        "records": [
            "Red-team finding records (F-numbers) with closure evidence; battery results.",
        ],
        "why": "To confirm security and resilience are evaluated adversarially and the findings are "
               "documented with honest closure criteria.",
        "likely_auditor_questions": [
            "Show your last red-team finding. What was the close-when criterion, and what re-verified it?",
        ],
        "common_failure_modes": [
            "Findings closed on green unit tests alone (the red-first post-wave audit rule exists to stop this).",
        ],
        "sampling_guidance": "Pull 2 closed findings; re-run their break batteries and confirm the "
                             "fix holds at the public seams.",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.9": {
        "documents": [
            "Output-interpretation guidance for operators/users.",
        ],
        "records": [
            "Lineage banner delivery events; tier-computation documentation.",
        ],
        "why": "To confirm AI output is explained and placed in context so humans use it responsibly — "
               "provenance is the mechanism here.",
        "likely_auditor_questions": [
            "How does a user know whether this output is verbatim memory or a derived paraphrase?",
        ],
        "common_failure_modes": [
            "Provenance metadata exists in storage but is never surfaced to the consumer.",
        ],
        "sampling_guidance": "Verify banner events exist for lineage-flagged recalls in the last 30 days.",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.13": {
        "documents": [
            "TEVV effectiveness review: how the measurement process itself is evaluated.",
        ],
        "records": [
            "Determinism-round results; anti-gaming rule change log; documented harness bugs "
            "and their fixes (scratch-contamination pair).",
        ],
        "why": "To confirm the yardstick is itself inspected — a gaming-vulnerable or nondeterministic "
               "harness produces evidence-grade numbers that mean nothing.",
        "likely_auditor_questions": [
            "How do you know your harness is not gameable? Show the anti-gaming rules.",
            "What was the last harness bug you found, and how did you prove the fix?",
        ],
        "common_failure_modes": [
            "Discarding contaminated scorecards instead of keeping them as measurement-hygiene evidence.",
        ],
        "sampling_guidance": "Confirm determinism rounds are recorded per scorecard; review the anti-gaming "
                             "rule list for the current harness version.",
    },
    "NIST-AI-RMF-1.0:MEASURE 3.1": {
        "documents": [
            "Risk-tracking approach: how existing, unanticipated, and emergent risks are "
            "identified and tracked over time.",
        ],
        "records": [
            "Chained log excerpts showing tracked risk events; canary/triage records.",
        ],
        "why": "To confirm risk tracking is continuous and tamper-evident — the log is the "
               "substrate, and its chain is the anti-tampering claim.",
        "likely_auditor_questions": [
            "Show how an emergent risk moved from detection to tracking to disposition.",
            "If someone edited the log, how would you know?",
        ],
        "common_failure_modes": [
            "Log rotation or truncation that breaks the chain (must fail closed, not silently).",
            "Key loss making historical chains unverifiable.",
        ],
        "sampling_guidance": "Verify the chain head for a sampled week; confirm key-custody "
                             "arrangements allow re-verification.",
    },
    "NIST-AI-RMF-1.0:MEASURE 4.2": {
        "documents": [
            "Domain-expert review procedure for measurement results.",
        ],
        "records": [
            "Reviewed scorecards with expert sign-off; residual-risk dispositions.",
        ],
        "why": "To confirm measurement results are validated by people who understand the domain, "
               "not just the harness authors.",
        "likely_auditor_questions": [
            "Who reviewed the last scorecard, and what did they dispute?",
        ],
        "common_failure_modes": [
            "Self-review by the harness author with no dissent recorded.",
        ],
        "sampling_guidance": "Check the last 2 scorecards for reviewer identity distinct from the author.",
    },
    "NIST-AI-RMF-1.0:MANAGE 1.4": {
        "documents": [
            "Residual-risk register: unmitigated risks communicated to downstream acquirers and users.",
        ],
        "records": [
            "Dated residual-risk entries with owner and review date.",
        ],
        "why": "To confirm negative residual risks are documented and communicated — the honest "
               "boundary is itself evidence.",
        "likely_auditor_questions": [
            "List the risks you have NOT mitigated. Who did you tell, and when?",
        ],
        "common_failure_modes": [
            "Residuals documented once and never reviewed; new findings not added.",
        ],
        "sampling_guidance": "Confirm the register lists the currently documented residuals "
                             "(a1-default-off, parametric-memory paraphrase, content-shape exfiltration) "
                             "with current review dates.",
    },
    "NIST-AI-RMF-1.0:MANAGE 2.3": {
        "documents": [
            "Unknown-risk response procedure: respond and recover when a new risk is identified.",
        ],
        "records": [
            "Finding records (F-numbers) with respond/recover trail and re-verification.",
        ],
        "why": "To confirm previously unknown risks trigger a followed procedure, not improvisation.",
        "likely_auditor_questions": [
            "Your last previously-unknown risk: walk me through response and recovery.",
        ],
        "common_failure_modes": [
            "Quiet patches without a finding record (the re-file rule exists to stop this).",
        ],
        "sampling_guidance": "Pull the most recent finding; confirm response, recovery, and "
                             "break-first re-verification are all recorded.",
    },
    "NIST-AI-RMF-1.0:MANAGE 2.4": {
        "documents": [
            "Disengagement/deactivation procedure: who may supersede or deactivate the system, and how.",
            "Assigned responsibilities for the kill path.",
        ],
        "records": [
            "Deactivation drills or actual deactivation records.",
        ],
        "why": "To confirm a misbehaving system can actually be stopped — mechanism in place, "
               "responsibility understood.",
        "likely_auditor_questions": [
            "Demonstrate the deactivation path. Who is paged, and what stops first?",
        ],
        "common_failure_modes": [
            "A documented kill switch that was never tested against the deployed topology.",
        ],
        "sampling_guidance": "Check the last drill date and that the drill covered the deployed "
                             "topology (all run dirs, all ledgers).",
    },
    "NIST-AI-RMF-1.0:MANAGE 3.1": {
        "documents": [
            "Third-party resource monitoring procedure and risk-control register.",
        ],
        "records": [
            "Trust-store reviews; verifier battery runs; card-verification rejection records.",
        ],
        "why": "To confirm third-party AI risks are monitored continuously and controls are applied "
               "and documented — not just assessed at onboarding.",
        "likely_auditor_questions": [
            "Since onboarding, what changed about your external agents, and what did you do?",
        ],
        "common_failure_modes": [
            "Onboarding checks never repeated; revoked keys still in the trust store.",
        ],
        "sampling_guidance": "Verify the trust store's last review date and that revoked entries "
                             "are actually rejected (not just listed).",
    },
    "NIST-AI-RMF-1.0:MANAGE 4.1": {
        "documents": [
            "Post-deployment monitoring plan: capture/evaluate user input, appeal and override, "
            "decommissioning, incident response, recovery, change management.",
        ],
        "records": [
            "Chained monitoring events; appeal/override records; change-management records.",
        ],
        "why": "To confirm monitoring is a plan that is implemented — with appeal, override, and "
               "change management — not just a log stream.",
        "likely_auditor_questions": [
            "Show an appeal or override and how it was dispositioned.",
            "What changed in the system last quarter, and where is the change record?",
        ],
        "common_failure_modes": [
            "Override paths that exist in the UI but are never tested or are admin-only in practice.",
        ],
        "sampling_guidance": "Sample 2 change records and 1 appeal/override; verify all are chained "
                             "with approver identity.",
    },
    "NIST-AI-RMF-1.0:MANAGE 4.3": {
        "documents": [
            "Incident communication plan: who is notified, when, and how.",
            "Tracking/response/recovery procedures.",
        ],
        "records": [
            "Curated incident exports with causal chains; notification records.",
        ],
        "why": "To confirm incidents are communicated to relevant actors and the full "
               "track-respond-recover loop is followed and documented.",
        "likely_auditor_questions": [
            "Your last incident: who was told, when, and what did the record contain?",
        ],
        "common_failure_modes": [
            "Incidents tracked internally but never communicated to affected parties.",
            "Root-cause pointers that dead-end (no linked log entries).",
        ],
        "sampling_guidance": "Pull the most recent incident export; verify the causal chain links "
                             "resolve to chained log entries and notifications are recorded.",
    },
    "EU-AI-ACT:Art.12(1)": {
        "documents": [
            "Logging specification: which events are recorded automatically, and for how long.",
            "Retention and storage policy.",
        ],
        "records": [
            "Sample log excerpts spanning the system lifetime; retention compliance evidence.",
        ],
        "why": "To confirm automatic event recording operates over the system's lifetime — the "
               "baseline record-keeping duty.",
        "likely_auditor_questions": [
            "Prove logging was continuous for this deployment's lifetime. Any gaps? Explain them.",
        ],
        "common_failure_modes": [
            "Logging that stops when a component is reconfigured; gaps with no explanation.",
        ],
        "sampling_guidance": "Verify chain continuity across the sampled period; any break must be "
                             "a fail-closed event, not a silent gap.",
    },
    "EU-AI-ACT:Art.12(2)(a)": {
        "documents": [
            "Definition of risk-relevant events for this system.",
        ],
        "records": [
            "Refusal, countermand, tier-escalation, and memory-pressure records with context.",
        ],
        "why": "To confirm the logs actually capture the events that let a provider identify "
               "risk-presenting situations — not just heartbeats.",
        "likely_auditor_questions": [
            "Show the logged events for your last refused exfiltration. What risk did they identify?",
        ],
        "common_failure_modes": [
            "Logs full of operational noise with risk events indistinguishable or missing context.",
        ],
        "sampling_guidance": "Sample 3 risk events; confirm each carries policy context and a "
                             "tamper-evident chain link.",
    },
    "EU-AI-ACT:Art.12(2)(b)": {
        "documents": [
            "Post-market monitoring plan (Annex IV) referencing the log data it consumes.",
        ],
        "records": [
            "Monitoring analyses derived from the logs.",
        ],
        "why": "To confirm logging feeds the Article 72 post-market monitoring — the two duties connect.",
        "likely_auditor_questions": [
            "Which monitoring analyses consumed these logs? Show one.",
        ],
        "common_failure_modes": [
            "A monitoring plan that cites logs it never actually reads.",
        ],
        "sampling_guidance": "Trace one monitoring conclusion back to the specific log entries it used.",
    },
    "EU-AI-ACT:Art.12(3)(d)": {
        "documents": [
            "Human-verification procedure (Art. 14(5)) and identity-management for verifiers.",
        ],
        "records": [
            "Approval receipts identifying the natural person who verified each result.",
        ],
        "why": "To confirm every verified result names the human who verified it — accountability "
               "is personal, not systemic.",
        "likely_auditor_questions": [
            "For this result: who verified it, when, and what did they see?",
        ],
        "common_failure_modes": [
            "Shared approver accounts (identity on the receipt is meaningless).",
        ],
        "sampling_guidance": "Sample 5 receipts; confirm decided_by resolves to a named natural person "
                             "with a distinct account.",
    },
    "EU-AI-ACT:Art.72(1)-(2)": {
        "documents": [
            "Post-market monitoring plan (part of technical documentation, Annex IV).",
            "Data-collection specification: which performance data, from where, how often.",
        ],
        "records": [
            "Collected lifetime performance data; documented analyses; resulting actions.",
        ],
        "why": "To confirm the provider actively and systematically collects and analyses lifetime "
               "performance data — the product supplies the feed; the provider runs the system.",
        "likely_auditor_questions": [
            "Show the last monitoring cycle: what data, what analysis, what action?",
        ],
        "common_failure_modes": [
            "A plan that exists but no monitoring cycle ever ran.",
        ],
        "sampling_guidance": "Verify at least one completed monitoring cycle with data, analysis, "
                             "and a disposition (even 'no action').",
    },
    "EU-AI-ACT:Art.72(3)": {
        "documents": [
            "The post-market monitoring plan itself, as part of the technical documentation.",
        ],
        "records": [
            "Version history of the plan; change records.",
        ],
        "why": "To confirm the plan exists as documentation, not just as practice.",
        "likely_auditor_questions": [
            "Produce the current plan. When was it last updated, and why?",
        ],
        "common_failure_modes": [
            "Plan version lagging the deployed system by multiple releases.",
        ],
        "sampling_guidance": "Check the plan's version against the deployed system version.",
    },
    "EU-AI-ACT:Art.73(1)-(2)": {
        "documents": [
            "Serious-incident reporting procedure: causal-link assessment, 15-day clock, authority contacts.",
        ],
        "records": [
            "Incident detection records; causal-link assessments; filed reports with timestamps.",
        ],
        "why": "To confirm serious incidents are reported to market surveillance authorities within "
               "the statutory window after the causal link is established.",
        "likely_auditor_questions": [
            "Your last serious incident: when did you become aware, when was the link established, "
            "when was it reported?",
        ],
        "common_failure_modes": [
            "Causal-link assessment that never concludes (clock never starts).",
        ],
        "sampling_guidance": "For the last incident, verify the three timestamps (awareness, link, "
                             "report) are recorded and ordered.",
    },
    "EU-AI-ACT:Art.73(6)": {
        "documents": [
            "Incident investigation procedure: risk assessment and corrective action.",
        ],
        "records": [
            "Investigation records with causal chains; risk assessments; corrective actions; "
            "authority cooperation records.",
        ],
        "why": "To confirm that after a report, the provider investigates without delay — "
               "risk assessment plus corrective action, cooperating with authorities.",
        "likely_auditor_questions": [
            "Show the investigation for the last reported incident. What corrective action resulted?",
        ],
        "common_failure_modes": [
            "Investigations that conclude 'no systemic issue' without addressing the causal chain.",
        ],
        "sampling_guidance": "Verify the corrective action is linked to the causal chain, not generic.",
    },
    "ISO-IEC-42001-2023:A.2": {
        "documents": ["AI policy document."],
        "records": ["Policy approval and review records."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Produce the AI policy and its approval record."],
        "common_failure_modes": ["Policy exists but is not communicated or enforced."],
        "sampling_guidance": "Confirm policy review date is current.",
    },
    "ISO-IEC-42001-2023:A.3.2": {
        "documents": ["Role/responsibility assignments for the AI system."],
        "records": ["Delegation receipts binding role, scope, and identity."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Who may delegate what to whom? Show a receipt."],
        "common_failure_modes": ["Delegation receipts exist but scopes are never enforced at execution."],
        "sampling_guidance": "Sample 3 receipts; verify scope and identity binding.",
    },
    "ISO-IEC-42001-2023:A.5.2": {
        "documents": ["AI impact assessment procedure."],
        "records": ["Completed impact assessments."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Show the impact assessment for the current deployment."],
        "common_failure_modes": ["Assessments completed once and never revisited."],
        "sampling_guidance": "Check the assessment date against the deployment date.",
    },
    "ISO-IEC-42001-2023:A.6.2.6": {
        "documents": ["Verification and validation plan."],
        "records": ["AMSB scorecards; battery results; determinism rounds."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it. "
               "The scorecards are quantitative V&V evidence.",
        "likely_auditor_questions": ["Reproduce the latest V&V evidence. What did it not cover?"],
        "common_failure_modes": ["V&V evidence for a configuration that is no longer deployed."],
        "sampling_guidance": "Match scorecard corpus/harness versions to the deployed build.",
    },
    "ISO-IEC-42001-2023:A.6.2.8": {
        "documents": ["Operation and monitoring procedures."],
        "records": ["Chained operational logs; egress ledger excerpts."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Show continuous operation monitoring for the last quarter."],
        "common_failure_modes": ["Monitoring gaps with no documented cause."],
        "sampling_guidance": "Verify chain continuity across the sampled period.",
    },
    "ISO-IEC-42001-2023:A.7.5": {
        "documents": ["Data provenance procedure."],
        "records": ["Lineage journal entries; memory provenance log excerpts."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Trace this output back to its ingested source."],
        "common_failure_modes": ["Provenance recorded but not consulted at read time."],
        "sampling_guidance": "Pick a lineage-flagged recall; verify the journal entry exists and "
                             "the banner was delivered.",
    },
    "ISO-IEC-42001-2023:A.8.2": {
        "documents": ["User/system documentation set."],
        "records": ["Published documentation versions."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Produce the documentation users receive."],
        "common_failure_modes": ["Documentation lagging the deployed version."],
        "sampling_guidance": "Check documentation version against deployed version.",
    },
    "ISO-IEC-42001-2023:A.8.4": {
        "documents": ["Incident communication procedure."],
        "records": ["Curated incident exports; notification records."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Show the communication record for the last incident."],
        "common_failure_modes": ["Internal tracking with no external communication."],
        "sampling_guidance": "Verify notification timestamps against the incident timeline.",
    },
    "ISO-IEC-42001-2023:A.9.2": {
        "documents": ["Responsible-use procedures (approval gates, memory governance)."],
        "records": ["Approval receipts; memory firewall tier logs."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["Demonstrate the approval gate and memory governance in operation."],
        "common_failure_modes": ["Procedures documented but bypassable in practice."],
        "sampling_guidance": "Attempt a high-tier action in a test deployment; confirm the gate fires.",
    },
    "ISO-IEC-42001-2023:A.10.3": {
        "documents": ["Supplier/third-party assessment procedure."],
        "records": ["A2A trust-store reviews; card verification battery results."],
        "why": "UNVERIFIED citation — confirm against the licensed standard before relying on it.",
        "likely_auditor_questions": ["How are external agents assessed before and after onboarding?"],
        "common_failure_modes": ["One-time onboarding assessment with no ongoing monitoring."],
        "sampling_guidance": "Check trust-store review cadence and revocation handling.",
    },
}

# Interview suggestions are per-framework-family, not per-control: auditors
# talk to people, and the right people depend on the control family.
_INTERVIEWEES = {
    "NIST-AI-RMF-1.0": [
        "AI risk owner / governance lead (GOVERN function)",
        "Deployment operator on duty (monitoring, incident response)",
        "Harness/eval engineer (MEASURE evidence)",
    ],
    "EU-AI-ACT": [
        "Provider's post-market monitoring responsible person (Art. 72)",
        "Incident reporting contact (Art. 73)",
        "Human-oversight supervisor (Art. 14/12(3)(d))",
    ],
    "ISO-IEC-42001-2023": [
        "AIMS management representative",
        "Internal audit lead",
    ],
}


def evidence_checklist(framework, control_id):
    """Return the evidence checklist for a registered control.

    Raises UnknownControlError for any (framework, control_id) not in
    CONTROL_REGISTRY — checklists are never invented.
    """
    key = "%s:%s" % (framework, control_id)
    reg = CONTROL_REGISTRY.get(key)
    if reg is None:
        raise UnknownControlError(
            "no checklist for unregistered control %r" % (key,))
    base = _CHECKLISTS.get(key)
    if base is None:
        raise UnknownControlError(
            "control %r is registered but has no checklist yet" % (key,))

    mechs = mechanisms_for_control(framework, control_id)
    system_artifacts = []
    for m in mechs:
        for kind in m["exports"]:
            system_artifacts.append({
                "artifact_kind": kind,
                "mechanism": m["mechanism_id"],
                "mechanism_name": m["mechanism_name"],
                "deployment_status": m["deployment_status"],
            })

    checklist = {
        "control": {
            "framework": framework,
            "control_id": control_id,
            "title": reg["title"],
            "mapping_status": reg["status"],
        },
        "documents": list(base["documents"]),
        "records": list(base["records"]),
        "system_artifacts": system_artifacts,
        "interviews": list(_INTERVIEWEES.get(framework, [])),
        "why": base["why"],
        "likely_auditor_questions": list(base["likely_auditor_questions"]),
        "common_failure_modes": list(base["common_failure_modes"]),
        "sampling_guidance": base["sampling_guidance"],
    }
    if reg["status"] == "unverified":
        checklist["control"]["verification_note"] = (
            "ISO/IEC 42001:2023 is a licensed standard; the numbered control "
            "text was not read from the primary source. Confirm against the "
            "licensed text before relying on this checklist.")
    else:
        checklist["control"]["verification_note"] = (
            "Control text read from the primary source on 2026-09-28.")
    return checklist
