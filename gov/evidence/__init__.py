"""Auditor-facing evidence index (evidence-matrix skeleton lane).

This package is READ-ONLY with respect to the product: it indexes the
evidence our enforcement mechanisms already emit, and maps each shipped
mechanism to the external controls it evidences. It changes no verdict,
no enforcement path, and no ledger format.

Direction is inverted relative to typical GRC tooling (cf.
mcp-ai-governance, MIT — contract shape only, no keyword mapper, no
readiness scores): we go mechanism -> controls (what the deployment
proves), never controls -> readiness-score. This package is decision
support for an auditor, not a certification claim and not legal advice.

Modules:
    crosswalk  — the hand-mapped mechanism -> controls table, with every
                 control citation carrying a mapping_status of "verified"
                 (checked against the primary source text) or "unverified"
                 (marked honestly, never invented).
    checklist  — the evidence_checklist contract: for a control, the
                 documents / records / system artifacts / interviews an
                 auditor will ask for, why each is requested, likely
                 auditor questions, common failure modes, sampling guidance.
    index      — the generator: scans a directory of live export artifacts
                 and emits a deterministic evidence-index document
                 (JSON + Markdown) a buyer hands an auditor.

$0, stdlib only, deterministic.
"""

from .checklist import UnknownControlError, evidence_checklist
from .crosswalk import (
    CONTROL_REGISTRY,
    FRAMEWORKS,
    KNOWN_ARTIFACT_KINDS,
    MECHANISMS,
    controls_for_mechanism,
    mechanisms_for_control,
)
from .index import generate_evidence_index, render_index_markdown

__all__ = [
    "CONTROL_REGISTRY",
    "FRAMEWORKS",
    "KNOWN_ARTIFACT_KINDS",
    "MECHANISMS",
    "UnknownControlError",
    "controls_for_mechanism",
    "evidence_checklist",
    "generate_evidence_index",
    "mechanisms_for_control",
    "render_index_markdown",
]
