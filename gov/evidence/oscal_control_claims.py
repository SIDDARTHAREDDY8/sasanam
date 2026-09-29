"""OSCAL v1.1.x component-definition extension: the NIST control-claim table.

ADDITIVE to (not a replacement of) ``gov/evidence/oscal_export.py``:
that module renders the mechanism -> controls crosswalk; this one
renders the control -> claim table from ``gov/control_claims.py`` --
one NIST SP 800-53 Rev 5 control implementation with an
``implemented-requirement`` per claim, each naming its automated
check, its evidence field, its narrow scope, and its explicit
non-claims. Controls we explicitly do NOT claim appear as
``implemented-requirement`` rows with ``x-claim-status: not-claimed``
and the reason -- absence is loud, never silent.

Honesty rules (same as gov/control_claims.py and oscal_export.py):
  - UUIDs are deterministic (uuid5 over a module-local fixed
    namespace) -- two runs are byte-identical.
  - metadata.remarks carries the decision-support-not-certification
    disclaimer; OSCAL is a format, not a proof.
  - metadata.props carries x-control-claims-sha256: sha256 over the
    canonical claim-table content, so an auditor can detect drift
    between this package and the claim table it renders.
  - This package does NOT assert that a check held at generation
    time. The check evaluations live in the red-team battery
    (evals/control_claim_probes.py) and in gov.control_claims itself;
    the requirement props point at the check name so an auditor can
    re-run it.
  - stdlib only, offline, $0, deterministic.
  - This module changes no enforcement path and no ledger format.

What this is NOT: an assessment. A claim row is evidence for an
assessor, never the assessment. Nothing here certifies compliance.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from gov.control_claims import (CLAIM_FIELDS, CONTROL_CLAIMS,
                                FRAMEWORK_ID, FRAMEWORK_NAME, NOT_CLAIMED)

__all__ = [
    "OSCAL_VERSION",
    "control_claims_content_digest",
    "generate_control_claims_component_definition",
    "component_definition_json",
]

OSCAL_VERSION = "1.1.3"
EXPORT_VERSION = "1.0.0"

# Fixed namespace, distinct from oscal_export's, so every UUID in THIS
# package is deterministic without colliding with the crosswalk export.
_PACKAGE_NAMESPACE = uuid.UUID("9f4a1c7e-2b8d-4e5f-a6c3-d7b09e1f2a64")


def _uid(*parts):
    return str(uuid.uuid5(_PACKAGE_NAMESPACE, "\x00".join(parts)))


def _prop(name, value):
    return {"name": name, "value": value}


_DISCLAIMER = (
    "This package is decision support for an auditor, not a certification "
    "claim and not legal advice. Each implemented-requirement names the "
    "automated check (gov/control_claims.CHECKS) that evaluates it and the "
    "evidence field an assessor inspects; checks are re-runnable, not "
    "pre-computed here. Controls not claimed by Sasanam are listed as "
    "not-claimed rows rather than omitted. The evidentiary value of this "
    "package is exactly the control-claim table's: OSCAL is a format, not "
    "a proof. Nothing here certifies compliance. NIST SP 800-53 Rev 5 is "
    "US public domain; control statements are paraphrases, not quotations."
)


def _canonical_claims_bytes(claims, not_claimed):
    """Canonical bytes of the rendered claim-table content.

    Public as a documented helper so the battery can assert the
    content digest is a real function of the table (sensitivity
    check), not a constant.
    """
    payload = {
        "framework_id": FRAMEWORK_ID,
        "claims": claims,
        "not_claimed": not_claimed,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def control_claims_content_digest():
    """sha256 hex of the canonical claim-table content."""
    return hashlib.sha256(
        _canonical_claims_bytes(CONTROL_CLAIMS, NOT_CLAIMED)).hexdigest()


def _claim_requirement(claim):
    return {
        "uuid": _uid("claim-requirement", FRAMEWORK_ID,
                     claim["control_id"]),
        "control-id": claim["control_id"],
        "description": "Claimed control: %s." % claim["nist_statement"],
        "props": [
            _prop("x-claim-status", "claimed"),
            _prop("x-nist-statement", claim["nist_statement"]),
            _prop("x-mechanism", claim["mechanism"]),
            _prop("x-claim-check", claim["check"]),
            _prop("x-evidence-field", claim["evidence_field"]),
            _prop("x-scope", claim["scope"]),
            _prop("x-not-claimed", claim["not_claimed"]),
        ],
        "by-components": [
            {
                "component-uuid": _uid("component", "control-claims"),
                "uuid": _uid("claim-by-component", FRAMEWORK_ID,
                             claim["control_id"]),
                "description": (
                    "Claim evaluated by the %s automated check against "
                    "the real modules (gov/control_claims.py)."
                    % claim["check"]),
            }
        ],
    }


def _not_claimed_requirement(entry):
    return {
        "uuid": _uid("not-claimed-requirement", FRAMEWORK_ID,
                     entry["control_id"]),
        "control-id": entry["control_id"],
        "description": "Not claimed: %s (%s)." % (entry["control_id"],
                                                  entry["title"]),
        "props": [
            _prop("x-claim-status", "not-claimed"),
            _prop("x-why-not", entry["why_not"]),
        ],
        "by-components": [],
    }


def _component():
    reqs = [_claim_requirement(c) for c in CONTROL_CLAIMS]
    reqs += [_not_claimed_requirement(e) for e in NOT_CLAIMED]
    return {
        "uuid": _uid("component", "control-claims"),
        "type": "software",
        "title": "Sasanam Control Claims (NIST SP 800-53 Rev 5)",
        "description": (
            "The control-claim table as code: every claim maps a NIST "
            "SP 800-53 Rev 5 control to its automated check, evidence "
            "field, narrow scope, and explicit non-claims; unclaimed "
            "controls are listed loudly."),
        "props": [
            _prop("x-framework-id", FRAMEWORK_ID),
            _prop("x-framework-name", FRAMEWORK_NAME),
            _prop("x-claim-fields", ",".join(CLAIM_FIELDS)),
            _prop("x-claimed-count", str(len(CONTROL_CLAIMS))),
            _prop("x-not-claimed-count", str(len(NOT_CLAIMED))),
        ],
        "control-implementations": [
            {
                "uuid": _uid("control-implementation", "control-claims",
                             FRAMEWORK_ID),
                "source": FRAMEWORK_ID,
                "description": (
                    "Claimed and not-claimed NIST SP 800-53 Rev 5 control "
                    "implementations (decision support, not certification)."),
                "props": [
                    _prop("x-framework-primary-source-checked", "true"),
                ],
                "implemented-requirements": reqs,
            }
        ],
    }


def generate_control_claims_component_definition(generated_at=None):
    """Build the OSCAL component-definition package as a dict.

    generated_at overrides the last-modified timestamp (for
    reproducible fixtures / byte-identical test comparisons);
    defaults to now (UTC).
    """
    return {
        "component-definition": {
            "uuid": _uid("component-definition", "control-claims"),
            "metadata": {
                "title": ("Agent Governance Control Claims "
                          "(OSCAL component-definition)"),
                "last-modified": generated_at or datetime.now(
                    timezone.utc).isoformat(),
                "oscal-version": OSCAL_VERSION,
                "version": EXPORT_VERSION,
                "remarks": _DISCLAIMER,
                "props": [
                    _prop("x-control-claims-sha256",
                          control_claims_content_digest()),
                    _prop("x-source", "gov/control_claims.py"),
                    _prop("x-export-module",
                          "gov/evidence/oscal_control_claims.py"),
                ],
            },
            "components": [_component()],
        }
    }


def component_definition_json(generated_at=None):
    """Canonical JSON serialization (sort_keys, indent 2)."""
    return json.dumps(
        generate_control_claims_component_definition(generated_at),
        sort_keys=True, indent=2, ensure_ascii=True) + "\n"
