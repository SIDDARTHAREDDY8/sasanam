"""Mechanism -> controls crosswalk (hand-mapped, never keyword-matched).

Every row names a SHIPPED mechanism in this tree, the implementation that
backs it, the export artifacts it emits, and the external controls it
evidences. Each control citation carries:

    framework       — one of FRAMEWORKS keys.
    control_id      — the control identifier as published.
    control_title   — the published title / duty summary.
    mapping_status  — "verified" or "unverified".
    verification_note — how the citation was checked (or why it is not).
    rationale       — why THIS mechanism evidences THIS control.
    residual        — what the mechanism does NOT prove (honest boundary).

"verified" means the control text was read from the primary source on
2026-09-28:
  - NIST AI RMF 1.0 (NIST.AI.100-1, Jan 2023, doi:10.6028/NIST.AI.100-1):
    subcategory texts read from the publication.
  - EU AI Act (Regulation (EU) 2024/1689): article texts read from the
    consolidated act.

"unverified" means the citation could NOT be checked against the primary
source (ISO/IEC 42001:2023 is paywalled; objective titles below were
cross-checked across multiple secondary reproductions but the numbered
control text was not read from the licensed standard). Unverified rows
are decision-support placeholders: an auditor must confirm them against
the licensed text before relying on them. Nothing here is invented.

The eval battery (evals/evidence_matrix_battery.py) pins:
  (a) every mechanism maps to >= 1 VERIFIED control;
  (b) every cited control_id is in CONTROL_REGISTRY (no invented IDs);
  (c) every ISO/IEC 42001 row is marked "unverified" with a note.
"""

FRAMEWORKS = {
    "NIST-AI-RMF-1.0": {
        "name": "NIST Artificial Intelligence Risk Management Framework 1.0",
        "citation": "NIST.AI.100-1, January 2023, doi:10.6028/NIST.AI.100-1",
        "primary_source_checked": True,
    },
    "EU-AI-ACT": {
        "name": "EU Artificial Intelligence Act",
        "citation": "Regulation (EU) 2024/1689",
        "primary_source_checked": True,
    },
    "ISO-IEC-42001-2023": {
        "name": "ISO/IEC 42001:2023 Artificial intelligence management system",
        "citation": "ISO/IEC 42001:2023 (licensed standard; text not read)",
        "primary_source_checked": False,
    },
}

# The registry of citable control IDs. The battery asserts every ID cited
# in MECHANISMS is a member here — an ID outside this registry is an
# invented control and fails the battery.
CONTROL_REGISTRY = {
    # NIST AI RMF 1.0 subcategories — texts verified 2026-09-28.
    "NIST-AI-RMF-1.0:GOVERN 4.2": {
        "title": "Organizational teams document the risks and potential impacts "
                 "of the AI technology they design, develop, deploy, evaluate, "
                 "and use, and they communicate about the impacts more broadly.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:GOVERN 4.3": {
        "title": "Organizational practices are in place to enable AI testing, "
                 "identification of incidents, and information sharing.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:GOVERN 5.1": {
        "title": "Organizational policies and practices are in place to collect, "
                 "consider, prioritize, and integrate feedback from those external "
                 "to the team that developed or deployed the AI system regarding "
                 "the potential individual and societal impacts related to AI risks.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:GOVERN 6.1": {
        "title": "Policies and procedures are in place that address AI risks "
                 "associated with third-party entities, including risks of "
                 "infringement of a third-party's intellectual property or other rights.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MAP 2.2": {
        "title": "Information about the AI system's knowledge limits and how "
                 "system output may be utilized and overseen by humans is documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MAP 3.5": {
        "title": "Processes for human oversight are defined, assessed, and "
                 "documented in accordance with organizational policies from the "
                 "GOVERN function.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MAP 4.1": {
        "title": "Approaches for mapping AI technology and legal risks of its "
                 "components - including the use of third-party data or software - "
                 "are in place, followed, and documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MAP 4.2": {
        "title": "Internal risk controls for components of the AI system, "
                 "including third-party AI technologies, are identified and documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 1.1": {
        "title": "Approaches and metrics for measurement of AI risks enumerated "
                 "during the MAP function are selected for implementation starting "
                 "with the most significant AI risks.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.1": {
        "title": "Test sets, metrics, and details about the tools used during "
                 "TEVV are documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.3": {
        "title": "AI system performance or assurance criteria are measured "
                 "qualitatively or quantitatively and demonstrated for conditions "
                 "similar to deployment setting(s). Measures are documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.4": {
        "title": "The functionality and behavior of the AI system and its "
                 "components - as identified in the MAP function - are monitored "
                 "when in production.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.7": {
        "title": "AI system security and resilience - as identified in the MAP "
                 "function - are evaluated and documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.9": {
        "title": "The AI model is explained, validated, and documented, and AI "
                 "system output is interpreted within its context - as identified "
                 "in the MAP function - to inform responsible use and governance.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 2.13": {
        "title": "Effectiveness of the employed TEVV metrics and processes in the "
                 "MEASURE function are evaluated and documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 3.1": {
        "title": "Approaches, personnel, and documentation are in place to "
                 "regularly identify and track existing, unanticipated, and "
                 "emergent AI risks based on factors such as intended and actual "
                 "performance in deployed contexts.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MEASURE 4.2": {
        "title": "Measurement results regarding AI system trustworthiness in "
                 "deployment context(s) and across the AI lifecycle are informed "
                 "by input from domain experts and relevant AI actors to validate "
                 "whether the system is performing consistently as intended. "
                 "Results are documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MANAGE 1.4": {
        "title": "Negative residual risks (defined as the sum of all unmitigated "
                 "risks) to both downstream acquirers of AI systems and end users "
                 "are documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MANAGE 2.3": {
        "title": "Procedures are followed to respond to and recover from a "
                 "previously unknown risk when it is identified.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MANAGE 2.4": {
        "title": "Mechanisms are in place and applied, and responsibilities are "
                 "assigned and understood, to supersede, disengage, or deactivate "
                 "AI systems that demonstrate performance or outcomes inconsistent "
                 "with intended use.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MANAGE 3.1": {
        "title": "AI risks and benefits from third-party resources are regularly "
                 "monitored, and risk controls are applied and documented.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MANAGE 4.1": {
        "title": "Post-deployment AI system monitoring plans are implemented, "
                 "including mechanisms for capturing and evaluating input from "
                 "users and other relevant AI actors, appeal and override, "
                 "decommissioning, incident response, recovery, and change management.",
        "status": "verified",
    },
    "NIST-AI-RMF-1.0:MANAGE 4.3": {
        "title": "Incidents and errors are communicated to relevant AI actors, "
                 "including affected communities. Processes for tracking, "
                 "responding to, and recovering from incidents and errors are "
                 "followed and documented.",
        "status": "verified",
    },
    # EU AI Act articles — texts verified 2026-09-28.
    "EU-AI-ACT:Art.12(1)": {
        "title": "High-risk AI systems shall technically allow for the automatic "
                 "recording of events (logs) over the lifetime of the system.",
        "status": "verified",
    },
    "EU-AI-ACT:Art.12(2)(a)": {
        "title": "Logging capabilities shall enable the recording of events "
                 "relevant for identifying situations that may result in the "
                 "high-risk AI system presenting a risk (Art. 79(1)) or a "
                 "substantial modification.",
        "status": "verified",
    },
    "EU-AI-ACT:Art.12(2)(b)": {
        "title": "Logging capabilities shall enable the recording of events "
                 "relevant for facilitating the post-market monitoring referred "
                 "to in Article 72.",
        "status": "verified",
    },
    "EU-AI-ACT:Art.12(3)(d)": {
        "title": "For Annex III point 1(a) high-risk AI systems, logging shall "
                 "provide at minimum the identification of the natural persons "
                 "involved in the verification of the results (Art. 14(5)).",
        "status": "verified",
    },
    "EU-AI-ACT:Art.72(1)-(2)": {
        "title": "Providers shall establish and document a post-market monitoring "
                 "system that actively and systematically collects, documents and "
                 "analyses relevant data on the performance of high-risk AI "
                 "systems throughout their lifetime.",
        "status": "verified",
    },
    "EU-AI-ACT:Art.72(3)": {
        "title": "The post-market monitoring system shall be based on a "
                 "post-market monitoring plan forming part of the technical "
                 "documentation (Annex IV).",
        "status": "verified",
    },
    "EU-AI-ACT:Art.73(1)-(2)": {
        "title": "Providers shall report any serious incident to the market "
                 "surveillance authorities of the Member States where it occurred, "
                 "immediately after establishing a causal link (or reasonable "
                 "likelihood), and in any event not later than 15 days after "
                 "becoming aware.",
        "status": "verified",
    },
    "EU-AI-ACT:Art.73(6)": {
        "title": "Following a serious-incident report, the provider shall without "
                 "delay perform the necessary investigations, including a risk "
                 "assessment of the incident and corrective action, and cooperate "
                 "with the competent authorities.",
        "status": "verified",
    },
    # ISO/IEC 42001:2023 — objective titles cross-checked across secondary
    # sources; numbered control text NOT read from the licensed standard.
    # All rows below are "unverified" by construction.
    "ISO-IEC-42001-2023:A.2": {
        "title": "Policies related to AI (control objective; includes AI policy).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.3.2": {
        "title": "AI roles and responsibilities (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.5.2": {
        "title": "AI impact assessment process (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.6.2.6": {
        "title": "Verification and validation (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.6.2.8": {
        "title": "Operation and monitoring (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.7.5": {
        "title": "Data provenance (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.8.2": {
        "title": "System documentation / information to users (per secondary "
                 "reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.8.4": {
        "title": "Incident communication (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.9.2": {
        "title": "Processes for responsible use (per secondary reproductions).",
        "status": "unverified",
    },
    "ISO-IEC-42001-2023:A.10.3": {
        "title": "Suppliers / third-party AI assessment (per secondary "
                 "reproductions).",
        "status": "unverified",
    },
}

_UNVERIFIED_ISO_NOTE = (
    "ISO/IEC 42001:2023 is a licensed standard; the numbered control text "
    "was not read from the primary source. Objective titles were "
    "cross-checked across multiple secondary reproductions. Confirm against "
    "the licensed standard before relying on this mapping."
)

# Export artifact kinds our mechanisms emit. The checklist and the index
# generator resolve evidence against these kinds only.
KNOWN_ARTIFACT_KINDS = (
    "chained_ledger",        # HMAC-chained JSONL (audit log, egress ledger, lineage journal)
    "approval_receipts",     # MAC-bound approval records + decision packets
    "delegation_receipts",   # delegation receipts (gov/delegation_tokens.py)
    "agent_card_trust_store", # A2A trust store + verification battery results
    "incident_export",       # gov/incident_export.py regulator-shaped export
    "offline_bundle",        # gov/offline_bundle.py auditor-verifiable bundle
    "evidence_bundle",       # gov/evidence_bundle.py signed governed-window export
    "policy_export",         # gov/policy_export.py deployed-policy translation
    "amsb_scorecard",        # evals/artifacts/amsb/ scorecard pairs
    "memory_provenance_log", # memory_write/memory_release ledger entries
)


def _m(mapping_status, verification_note, rationale, residual):
    return {
        "mapping_status": mapping_status,
        "verification_note": verification_note,
        "rationale": rationale,
        "residual": residual,
    }


def _verified(rationale, residual):
    return _m("verified",
              "Control text read from the primary source on 2026-09-28.",
              rationale, residual)


def _unverified_iso(rationale, residual):
    return _m("unverified", _UNVERIFIED_ISO_NOTE, rationale, residual)


MECHANISMS = [
    {
        "id": "chained-audit-log",
        "name": "HMAC-chained audit log",
        "description": (
            "Append-only, HMAC-SHA256 hash-chained JSONL audit log "
            "(gov/chained_store.py ChainedStore). Fails closed without "
            "configured keys; key-provider seam supports HashiCorp Vault "
            "transit. Every governed event (policy decisions, approvals, "
            "refusals, egress, memory operations) is chained; a broken "
            "chain is tamper evidence, never silently skipped."
        ),
        "implementation": ["gov/chained_store.py"],
        "exports": ["chained_ledger", "evidence_bundle", "offline_bundle"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MEASURE 3.1", _verified(
                "The chained log is the substrate that regularly identifies "
                "and tracks existing, unanticipated, and emergent AI risks: "
                "every governed decision and refusal is recorded with its "
                "policy context, tamper-evidently.",
                "The log records what happened; it does not by itself "
                "identify which events constitute emergent risk — that "
                "analysis is the operator's (cf. canary_causation.py triage).")),
            ("NIST-AI-RMF-1.0", "MANAGE 4.1", _verified(
                "Post-deployment monitoring is implemented as continuous "
                "chained logging with incident-response, recovery, and change "
                "events as first-class chained entries.",
                "Monitoring plans, appeal/override workflows, and "
                "decommissioning procedures are organizational; the log is "
                "the record, not the plan.")),
            ("NIST-AI-RMF-1.0", "MANAGE 4.3", _verified(
                "Incidents and errors are tracked as chained entries; "
                "gov/incident_export.py curates causal chains and root-cause "
                "pointers from the log for communication to relevant actors.",
                "Communication to affected communities is the operator's "
                "duty; the product supplies the curated, verifiable record.")),
            ("EU-AI-ACT", "Art.12(1)", _verified(
                "Automatic recording of events (logs) over the lifetime of "
                "the system is the log's primary function.",
                "Retention policy and storage durability are deployment "
                "configuration, not product behavior.")),
            ("EU-AI-ACT", "Art.12(2)(a)", _verified(
                "Risk-relevant events (refusals, countermands, tier "
                "escalations, memory-pressure degradation) are recorded with "
                "policy context, enabling identification of risk-presenting "
                "situations.",
                "The Article 79 risk determination itself is the provider's "
                "legal assessment.")),
            ("EU-AI-ACT", "Art.72(1)-(2)", _verified(
                "The log is the data source a provider's post-market "
                "monitoring system collects, documents, and analyses: "
                "lifetime performance data with integrity guarantees.",
                "The monitoring system, plan, and corrective actions are the "
                "provider's; the product supplies the evidence feed.")),
            ("ISO-IEC-42001-2023", "A.6.2.8", _unverified_iso(
                "Continuous operation monitoring is implemented as "
                "tamper-evident chained logging of all governed operations.",
                "Confirm control text against the licensed standard.")),
            ("ISO-IEC-42001-2023", "A.8.4", _unverified_iso(
                "Incident communication is supported by curated, verifiable "
                "incident exports derived from the chained log.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "approval-receipts",
        "name": "Human approval receipts (canonical-target binding)",
        "description": (
            "Human-in-the-loop approval queue (gov/approvals.py): every "
            "approval produces a MAC-bound record with the machine-generated "
            "decision packet (canonical_packet, packet_version 5), the "
            "human's identity (decided_by), reason, risk tier, blast radius, "
            "and policy citations. The queue-time canonical target "
            "(policy_context.path_resolved) rides the MAC-bound snapshot. "
            "STATUS NOTE (2026-09-28, wave-171): the F190 canonical-target "
            "binding is in the tree — the receipt MAC-binds the queue-time "
            "canonical target, the decision packet renders it alongside the "
            "declared target, and the approved sweep refuses fail-closed "
            "(canonical_target_mismatch) when the sweep-time resolution "
            "differs from the bound value. Demonstrated by "
            "evals/f190_target_binding_battery.py: p1/p4 TOCTOU probes "
            "FIXED (refused, nothing executed), p2/p3 controls HELD. "
            "Fail-closed upgrade note (wave-171, F190): pre-upgrade "
            "queued records (packet_version 2) failed decide() packet "
            "re-verification. Wave-173 note: packet_version is now 4 "
            "(TMA-NM act-time gate disclosure) and the decision record "
            "MAC-binds the review-timing triple (gov/ceremony_integrity.py) "
            "— pre-upgrade queued records (packet_version 3, no timing "
            "triple) fail re-verification fail-closed. Drain or decide "
            "queued items before upgrading. Wave-174 (F191) note: "
            "packet_version is now 5 (attachment-carrier disclosure "
            "joins the WYSINWYS packet) — pre-upgrade queued records "
            "(packet_version 4, no carrier disclosure) fail "
            "re-verification fail-closed. Drain or decide queued items "
            "before upgrading."
        ),
        "implementation": ["gov/approvals.py", "gov/approval_web.py",
                           "gov/approver_shield.py"],
        "exports": ["approval_receipts", "chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MAP 3.5", _verified(
                "Human oversight is defined (approval queue, decision packet, "
                "re-presentation on refusal), assessed (decision-replay "
                "battery), and documented (chained approval records).",
                "Oversight policy (which actions require approval) is the "
                "operator's policy.yaml, not the product.")),
            ("NIST-AI-RMF-1.0", "GOVERN 4.2", _verified(
                "Each approval record documents the risk the organizational "
                "team accepted (risk tier, factors, blast radius) and "
                "communicates it via the chained, exportable record.",
                "Broader communication of impacts is organizational.")),
            ("EU-AI-ACT", "Art.12(3)(d)", _verified(
                "The natural person verifying the result is identified on "
                "every receipt (decided_by) with a timestamped, MAC-bound "
                "record.",
                "Applies to Annex III 1(a) systems; the provider determines "
                "applicability.")),
            ("ISO-IEC-42001-2023", "A.9.2", _unverified_iso(
                "Responsible-use processes are enforced as human approval "
                "gates with bound, auditable receipts.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "lineage",
        "name": "Memory lineage cap + cross-session lineage journal",
        "description": (
            "Wave-169: read-time lineage_shaped_source flag — paraphrases "
            "derived from shaped ingestion are delivered with a provenance "
            "banner and warning, never silently (tier ontology untouched). "
            "Wave-170: LineageJournal (gov/memory_provenance.py) — "
            "per-deployment, append-only, HMAC-chained journal of "
            "(principal, fingerprint, flag) consulted at read time across "
            "session boundaries; tamper fails closed. Together they bound "
            "how much trust derived memory content may carry."
        ),
        "implementation": ["gov/memory_provenance.py"],
        "exports": ["memory_provenance_log", "chained_ledger", "amsb_scorecard"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MAP 2.2", _verified(
                "Knowledge limits are documented at the point of use: the "
                "banner communicates the trust limit of derived content to "
                "the human/agent consuming it.",
                "The banner is a trust signal, not a content-truth claim.")),
            ("NIST-AI-RMF-1.0", "MEASURE 2.9", _verified(
                "AI system output is interpreted within its context: the "
                "provenance banner + warning place derived memory output in "
                "its lineage context to inform responsible use and governance.",
                "Parametric-memory paraphrase (no ingestion) remains an "
                "honest residual.")),
            ("ISO-IEC-42001-2023", "A.7.5", _unverified_iso(
                "Data provenance is tracked from ingestion through derivation "
                "to recall, with tamper-evident lineage records.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "memory-firewall",
        "name": "Memory firewall (tiered memory governance)",
        "description": (
            "MemoryFirewall (gov/memory_provenance.py): path scoping, "
            "per-write tier computation (verbatim-overlap + policy), and "
            "read-time checks. Construction is opt-in by the deployment; all "
            "tier computation is centralized here, never in the executor."
        ),
        "implementation": ["gov/memory_provenance.py"],
        "exports": ["memory_provenance_log", "chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MAP 4.2", _verified(
                "The firewall is an identified, documented internal risk "
                "control for the memory component of the AI system.",
                "Effectiveness against a given threat class is measured by "
                "the eval batteries, not asserted by the control's existence.")),
            ("NIST-AI-RMF-1.0", "MAP 2.2", _verified(
                "Tier computation documents what the system may treat as "
                "trusted memory vs. untrusted/shaped content.",
                "Tier ontology is deployment policy surface.")),
            ("ISO-IEC-42001-2023", "A.9.2", _unverified_iso(
                "Responsible-use processes include memory read/write "
                "governance with tiered trust.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "delegation-receipts",
        "name": "Delegation receipts (card-bound)",
        "description": (
            "Delegation tokens (gov/delegation_tokens.py): scoped, MAC-bound "
            "delegation receipts; when an A2A Agent Card is verified, the "
            "receipt binds card_kid and the verified card identity must equal "
            "the delegation subject. Local non-card receipts remain supported."
        ),
        "implementation": ["gov/delegation_tokens.py", "gov/agent_cards.py"],
        "exports": ["delegation_receipts", "chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MAP 4.2", _verified(
                "Delegation is an identified, documented internal risk "
                "control: scope, subject identity binding, and receipt "
                "chaining are enforced, not advisory.",
                "Cross-organization delegation policy is the operator's.")),
            ("ISO-IEC-42001-2023", "A.3.2", _unverified_iso(
                "AI roles and responsibilities are bound cryptographically: "
                "a delegation receipt states who may act as whom, within "
                "what scope.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "a2a-card-verification",
        "name": "A2A signed Agent Card verification",
        "description": (
            "Fail-closed A2A v1 signed-Agent-Card verifier "
            "(gov/agent_cards.py): EdDSA via the repo's RFC 8032 Ed25519 "
            "implementation, strict algorithm allow-list, jku never fetched "
            "(SSRF/key-substitution surface), ambiguous/unknown kids "
            "rejected, stale trust data rejected. Establishes runtime "
            "identity; the delegation receipt remains the action "
            "authorization."
        ),
        "implementation": ["gov/agent_cards.py"],
        "exports": ["agent_card_trust_store", "chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "GOVERN 6.1", _verified(
                "Third-party entity risk is addressed procedurally: external "
                "agent identity claims are verified against a pinned trust "
                "store before any delegation is honored.",
                "IP/infringement risk assessment is the operator's.")),
            ("NIST-AI-RMF-1.0", "MAP 4.1", _verified(
                "Third-party software/data risk mapping includes runtime "
                "identity verification of external agents as a mapped, "
                "documented approach.",
                "Legal risk mapping is organizational.")),
            ("NIST-AI-RMF-1.0", "MANAGE 3.1", _verified(
                "Third-party resource risk controls (card verification, "
                "trust-store freshness) are applied and documented; the "
                "28/28 verifier battery is the documented evidence.",
                "Ongoing monitoring cadence is deployment policy.")),
            ("ISO-IEC-42001-2023", "A.10.3", _unverified_iso(
                "Supplier (external agent) assessment is enforced at runtime "
                "via signed identity verification.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "capability-manifests",
        "name": "Signed capability manifests bound to artifact digest",
        "description": (
            "smithmark-shaped (R6 stream-2) signed declared-capability "
            "attestations (gov/capability_manifests.py): a manifest binds "
            "declared capabilities (tools, egress, filesystem, exec, env, "
            "secrets) to the artifact's sha256 digest under an Ed25519 "
            "signature from the deployment-pinned ManifestStore (the "
            "agent-card signature envelope; jku key discovery is refused "
            "outright). At skill/MCP use time the watcher verifies the "
            "signature, the digest binding, and that the statically "
            "detected capability surface does not exceed the declaration; "
            "any mismatch refuses the load fail-closed. Skills with no "
            "published manifest keep today's behavior with an advisory "
            "capability_manifest_absent event (audit-only adoption)."
        ),
        "implementation": ["gov/capability_manifests.py",
                           "gov/skill_watch.py"],
        "exports": ["chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MAP 4.1", _verified(
                "Third-party software component risks are mapped as signed "
                "declared-capability attestations bound to the component's "
                "digest, and enforced at every use — drift beyond the "
                "declared scope is refused, not merely observed.",
                "The static capability lint is category-granular and "
                "best-effort: obfuscated capability use evades it; the "
                "digest binding and signature are the hard guarantees.")),
            ("NIST-AI-RMF-1.0", "MANAGE 3.1", _verified(
                "Third-party resource risk controls (manifest signature, "
                "digest binding, capability-surface check) are applied at "
                "skill/MCP load time; the 12-probe capability-manifest "
                "battery is the documented evidence.",
                "Manifest publication coverage is deployment policy.")),
            ("ISO-IEC-42001-2023", "A.10.3", _unverified_iso(
                "Supplier component assessment is enforced at runtime via "
                "signed capability declarations bound to artifact digests.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "egress-ledger",
        "name": "Tiered egress ledger",
        "description": (
            "Per-principal, tamper-evident, cross-run record of outbound data "
            "movement (gov/egress_ledger.py): every egress is tiered "
            "(operational row-13 tiered egress) and chained; exfiltration- "
            "shaped egress is refused or tiered-loud, never silent."
        ),
        "implementation": ["gov/egress_ledger.py"],
        "exports": ["chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MEASURE 2.4", _verified(
                "The behavior of the AI system in production — specifically "
                "its outbound data movement — is monitored and recorded "
                "per principal, tamper-evidently.",
                "Content-shape exfiltration remains a PARTIAL row-12 "
                "residual; the ledger records, it does not inspect content.")),
            ("NIST-AI-RMF-1.0", "MEASURE 3.1", _verified(
                "Egress patterns are tracked over time, supporting "
                "identification of unanticipated exfiltration-shaped risks.",
                "Anomaly detection over the ledger is operator analysis.")),
            ("EU-AI-ACT", "Art.12(2)(a)", _verified(
                "Egress events relevant to identifying risk-presenting "
                "situations (tier escalations, refused exfiltration) are "
                "recorded.",
                "Risk determination is the provider's.")),
            ("ISO-IEC-42001-2023", "A.6.2.8", _unverified_iso(
                "Operation monitoring includes outbound data-movement "
                "accounting per principal.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "amsb-scorecards",
        "name": "AMSB adversarial evidence scorecards",
        "description": (
            "OWASP Agent Memory Guard benchmark harness graft "
            "(evals/amsb_*): per-scenario fresh-adapter corpus, severity "
            "weights 1/2/3/4, FP penalty up to 40, critical-breach grade "
            "ceilings, determinism rounds. Scorecards are versioned JSON+TXT "
            "pairs under evals/artifacts/amsb/ — quantitative, "
            "auditor-readable evidence of memory-safety posture, including "
            "honest residual breaches (e.g. documented a1-default-off)."
        ),
        "implementation": ["evals/amsb_corpus.py", "evals/amsb_run.py",
                           "evals/amsb_score.py"],
        "exports": ["amsb_scorecard"],
        "deployment_status": "shipped",
        "controls": [
            ("NIST-AI-RMF-1.0", "MEASURE 1.1", _verified(
                "Memory-safety risks are measured with selected approaches "
                "and metrics, starting with the most significant (severity-"
                "weighted scenarios, critical-breach ceilings).",
                "Coverage is the documented corpus, not the universe of "
                "attacks.")),
            ("NIST-AI-RMF-1.0", "MEASURE 2.1", _verified(
                "Test sets (versioned corpus), metrics (severity weights, FP "
                "penalty, grade formula), and tool details (fresh-adapter "
                "harness, anti-gaming rules) are documented with every "
                "scorecard.",
                "The harness measures the deployment's configuration, not a "
                "universal product claim.")),
            ("NIST-AI-RMF-1.0", "MEASURE 2.3", _verified(
                "Assurance criteria are measured quantitatively and "
                "demonstrated under deployment-like conditions; measures are "
                "documented per scorecard.",
                "Scores are point-in-time for the tested configuration.")),
            ("NIST-AI-RMF-1.0", "MEASURE 2.13", _verified(
                "TEVV effectiveness is itself evaluated: anti-gaming rules, "
                "determinism rounds, and the documented scratch-contamination "
                "bug found and fixed in wave-170 are evidence of measurement "
                "hygiene.",
                "Harness bugs are possible; the contamination-evidence "
                "scorecard pair is kept as the record.")),
            ("NIST-AI-RMF-1.0", "GOVERN 4.3", _verified(
                "AI testing practices are in place and shareable: scorecards "
                "are versioned, reproducible artifacts suitable for "
                "information sharing with relevant actors.",
                "Sharing cadence and audience are organizational.")),
            ("ISO-IEC-42001-2023", "A.6.2.6", _unverified_iso(
                "Verification and validation evidence is produced as "
                "quantitative, reproducible scorecards.",
                "Confirm control text against the licensed standard.")),
        ],
    },
    {
        "id": "incident-export",
        "name": "Regulator-shaped incident export",
        "description": (
            "gov/incident_export.py: detects incidents from the chained log, "
            "curates causal chains with root-cause pointers, and emits a "
            "regulator-shaped export (EU AI Act Art. 73 / Art. 50 framing) "
            "with anchor receipts; gov/evidence_exports.py provides the "
            "serious-incident report exports."
        ),
        "implementation": ["gov/incident_export.py", "gov/evidence_exports.py"],
        "exports": ["incident_export", "chained_ledger"],
        "deployment_status": "shipped",
        "controls": [
            ("EU-AI-ACT", "Art.73(1)-(2)", _verified(
                "Serious-incident detection, curation, and export produce the "
                "record a provider reports to market surveillance authorities "
                "within the statutory window.",
                "Filing the report on time is the provider's duty; the "
                "product supplies the complete, verifiable record.")),
            ("EU-AI-ACT", "Art.73(6)", _verified(
                "The curated causal chain and root-cause pointers are the "
                "investigative substrate for the required risk assessment and "
                "corrective action.",
                "The investigation and corrective action are the provider's.")),
            ("NIST-AI-RMF-1.0", "MANAGE 4.3", _verified(
                "Incident tracking, response, and recovery processes are "
                "followed and documented via the curated export.",
                "Communication to affected communities is organizational.")),
            ("NIST-AI-RMF-1.0", "MANAGE 2.3", _verified(
                "Previously unknown risks, once identified as incidents, flow "
                "through a documented respond-and-recover path.",
                "Response procedures are organizational.")),
            ("ISO-IEC-42001-2023", "A.8.4", _unverified_iso(
                "Incident communication artifacts are generated in a "
                "verifiable, regulator-shaped form.",
                "Confirm control text against the licensed standard.")),
        ],
    },
]


def controls_for_mechanism(mech_id):
    """Verified+unverified control rows for a mechanism id."""
    for m in MECHANISMS:
        if m["id"] == mech_id:
            return [
                {
                    "framework": fw,
                    "control_id": cid,
                    "control_title": CONTROL_REGISTRY["%s:%s" % (fw, cid)]["title"],
                    **detail,
                }
                for (fw, cid, detail) in m["controls"]
            ]
    raise KeyError("unknown mechanism: %r" % (mech_id,))


def mechanisms_for_control(framework, control_id):
    """Invert the crosswalk: which mechanisms evidence a control."""
    key = "%s:%s" % (framework, control_id)
    if key not in CONTROL_REGISTRY:
        raise KeyError("unknown control: %r" % (key,))
    out = []
    for m in MECHANISMS:
        for (fw, cid, detail) in m["controls"]:
            if fw == framework and cid == control_id:
                out.append({"mechanism_id": m["id"],
                            "mechanism_name": m["name"],
                            "deployment_status": m["deployment_status"],
                            "exports": list(m["exports"]),
                            **detail})
    return out


def mechanism_ids():
    return [m["id"] for m in MECHANISMS]
