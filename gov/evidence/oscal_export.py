"""OSCAL v1.1.x component-definition export of the evidence crosswalk.

Derived FORMAT, primary DATA: this module renders the hand-mapped
mechanism -> controls crosswalk (gov/evidence/crosswalk.py) as a NIST
OSCAL v1.1.x component-definition package so auditor GRC tooling can
ingest it. Every shipped mechanism becomes a component; every control
mapping becomes an implemented-requirement under the mechanism's
per-framework control-implementation.

Honesty rules (same as the crosswalk):
  - UUIDs are deterministic (uuid5 over a fixed namespace) — two runs
    are byte-identical, and a UUID identifies the same (mechanism,
    framework, control) tuple forever.
  - mapping-status rides every implemented-requirement as a prop;
    ISO/IEC 42001:2023 rows keep mapping-status=unverified plus the
    licensed-text verification note — exactly as the crosswalk has them.
  - metadata.remarks carries the decision-support-not-certification
    disclaimer.
  - metadata.props carries x-crosswalk-sha256: sha256 over the canonical
    crosswalk content, so an auditor can detect drift between this
    package and the bespoke evidence index.
  - stdlib only, offline, $0, deterministic.

What this is NOT: the export's evidentiary value is exactly the
crosswalk's — OSCAL is a format, not a proof. A future auditor tool may
expect OSCAL profiles we don't emit (we ship component-definition
only, not catalog/profile/assessment-results).

This module changes no enforcement path and no ledger format.
"""

import hashlib
import json
import uuid
from datetime import datetime, timezone

from .crosswalk import CONTROL_REGISTRY, FRAMEWORKS, MECHANISMS

__all__ = [
    "OSCAL_VERSION",
    "component_definition_json",
    "crosswalk_content_digest",
    "generate_oscal_component_definition",
]

OSCAL_VERSION = "1.1.3"
EXPORT_VERSION = "1.0.0"

# Fixed namespace so every UUID in the package is deterministic.
_PACKAGE_NAMESPACE = uuid.UUID("7c9b8e3a-1f2d-4a5b-9c6e-3f8a2b1d4e5c")


def _uid(*parts):
    return str(uuid.uuid5(_PACKAGE_NAMESPACE, "\x00".join(parts)))


def _canonical_crosswalk_bytes(mechanisms, registry, frameworks):
    """Canonical bytes of the crosswalk content (sort_keys, compact).

    Public as a documented helper so the battery can assert the
    content digest is a real function of the crosswalk data (sensitivity
    check), not a constant.
    """
    payload = {
        "frameworks": frameworks,
        "registry": registry,
        "mechanisms": mechanisms,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def crosswalk_content_digest():
    """sha256 hex of the canonical crosswalk content."""
    return hashlib.sha256(
        _canonical_crosswalk_bytes(MECHANISMS, CONTROL_REGISTRY, FRAMEWORKS)
    ).hexdigest()


def _prop(name, value):
    return {"name": name, "value": value}


_DISCLAIMER = (
    "This package is decision support for an auditor, not a certification "
    "claim and not legal advice. 'verified' control citations were checked "
    "against the primary source text on 2026-09-28 (NIST AI RMF 1.0, "
    "Regulation (EU) 2024/1689). 'unverified' citations (ISO/IEC 42001:2023 "
    "— a licensed standard whose numbered control text was not read) were "
    "cross-checked across secondary reproductions and must be confirmed "
    "against the licensed text before being relied upon. The evidentiary "
    "value of this package is exactly the evidence crosswalk's: OSCAL is a "
    "format, not a proof. Nothing here certifies compliance."
)


def _implemented_requirement(mechanism_id, framework, control_id, detail):
    reg_key = "%s:%s" % (framework, control_id)
    reg = CONTROL_REGISTRY[reg_key]
    return {
        "uuid": _uid("implemented-requirement", mechanism_id, framework,
                     control_id),
        "control-id": control_id,
        "description": reg["title"],
        "props": [
            _prop("mapping-status", detail["mapping_status"]),
            _prop("x-verification-note", detail["verification_note"]),
            _prop("x-rationale", detail["rationale"]),
            _prop("x-residual", detail["residual"]),
        ],
        "by-components": [
            {
                "component-uuid": _uid("component", mechanism_id),
                "uuid": _uid("by-component", mechanism_id, framework,
                             control_id),
                "description": (
                    "Implemented by the %s mechanism (%s)." %
                    (mechanism_id, framework)),
            }
        ],
    }


def _component(mechanism):
    mid = mechanism["id"]
    impls = []
    # Group the mechanism's mappings by framework (deterministic order).
    by_fw = {}
    for (fw, cid, detail) in mechanism["controls"]:
        by_fw.setdefault(fw, []).append((cid, detail))
    for fw in sorted(by_fw):
        reqs = [_implemented_requirement(mid, fw, cid, detail)
                for (cid, detail) in
                sorted(by_fw[fw], key=lambda t: t[0])]
        impls.append({
            "uuid": _uid("control-implementation", mid, fw),
            "source": fw,
            "description": (
                "Control mappings of the %s mechanism against %s "
                "(%s)." % (mechanism["name"], fw,
                            FRAMEWORKS[fw]["citation"])),
            "props": [
                _prop("x-framework-primary-source-checked",
                      "true" if FRAMEWORKS[fw]["primary_source_checked"]
                      else "false"),
            ],
            "implemented-requirements": reqs,
        })
    return {
        "uuid": _uid("component", mid),
        "type": "software",
        "title": mechanism["name"],
        "description": mechanism["description"],
        "props": [
            _prop("x-mechanism-id", mid),
            _prop("x-deployment-status", mechanism["deployment_status"]),
            _prop("x-implementation",
                  ", ".join(mechanism["implementation"])),
            _prop("x-exports", ", ".join(mechanism["exports"])),
        ],
        "control-implementations": impls,
    }


def generate_oscal_component_definition(generated_at=None):
    """Build the OSCAL component-definition package as a dict.

    generated_at overrides the last-modified timestamp (for
    reproducible fixtures / byte-identical test comparisons);
    defaults to now (UTC).
    """
    components = [_component(m) for m in sorted(
        MECHANISMS, key=lambda m: m["id"])]
    return {
        "component-definition": {
            "uuid": _uid("component-definition"),
            "metadata": {
                "title": ("Agent Governance Evidence Crosswalk "
                          "(OSCAL component-definition)"),
                "last-modified": generated_at or datetime.now(
                    timezone.utc).isoformat(),
                "oscal-version": OSCAL_VERSION,
                "version": EXPORT_VERSION,
                "remarks": _DISCLAIMER,
                "props": [
                    _prop("x-crosswalk-sha256", crosswalk_content_digest()),
                    _prop("x-source", "gov/evidence/crosswalk.py"),
                    _prop("x-export-module",
                          "gov/evidence/oscal_export.py"),
                ],
            },
            "components": components,
        }
    }


def component_definition_json(generated_at=None):
    """Canonical JSON serialization (sort_keys, indent 2)."""
    return json.dumps(generate_oscal_component_definition(generated_at),
                      sort_keys=True, indent=2, ensure_ascii=True) + "\n"
