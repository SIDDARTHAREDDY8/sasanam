"""Single-source compliance emitter (wave-254 lane 3).

ComplianceAsCode/content ADAPT -- the single control source emitting
multi-format regulator artifacts. Pattern only; no ComplianceAsCode
code or its content model.

A control source is ONE dict::

    {
        "id": "SAS-COMP-001",
        "title": "Permit lifecycle evidence is tamper-evident",
        "description": "Bound permits are journaled in a hash-chained "
                       "journal and exportable as auditor evidence.",
        "mappings": [
            {"kind": "code", "ref": "permit-journal-misuse",
             "rationale": "refusal path for malformed journal events"},
            {"kind": "finding", "ref": "F214",
             "rationale": "linked red-team finding"},
            {"kind": "mechanism", "ref": "chained-audit-log",
             "rationale": "hash-chained append-only log"},
            {"kind": "posture_track", "ref": "durability",
             "rationale": "durability track covers journal health"},
        ],
    }

Evidence resolution is live and fail-closed:
  - kind=code: ref must exist in gov.decision_codes.TAXONOMY.
  - kind=mechanism: ref must be a mechanism id in
    gov.evidence.crosswalk.MECHANISMS.
  - kind=posture_track: ref must be in gov.posture_cards.TRACKS
    (the closed track vocabulary).
  - kind=finding: ref is validated against the deployment-supplied
    ``findings`` mapping (finding_id -> "open" | "closed"). Findings
    live in the prose register (evals/FINDINGS.md), not in code, so
    the deployment owns the index -- an absent index or an unknown
    id fails closed (never assumed present, never assumed closed).

A control with zero mappings is refused
(``compliance-emitter-unlinked-claim``): no artifact is ever emitted
for a claim with no evidence link.

Emitters (all deterministic; every artifact carries the
x-compliance-source-sha256 digest of the normalized source +
resolved finding statuses, so an auditor can detect drift):
  - emit_oscal: OSCAL v1.1.x component-definition. uuid5 UUIDs,
    decision-support disclaimer, and the digest-bound metadata
    pattern mirror gov/evidence/oscal_export.py.
  - emit_markdown: human-readable compliance summary document.
  - emit_json: machine-readable canonical-JSON control mapping.
  - emit(source, fmt, ...): dispatcher over the closed format set.

Honest boundaries (documented, not hidden):
  - An emitted artifact proves the emitter RAN over the referenced
    evidence -- it does not re-verify that evidence. A code in the
    taxonomy is a refusal path, not proof the deployment triggers
    it; a mechanism in the crosswalk is a claimed mapping, not proof
    the deployment runs it. The JSON artifact states this per
    mapping so no auditor mistakes the emitter for a verifier.
  - Finding statuses come from the deployment index; the emitter
    does not authenticate that index.
  - OSCAL is a format, not a proof (same as gov/evidence).

Stdlib only. No enforcement path is touched.
"""

import copy
import hashlib
import json
import uuid
from datetime import datetime, timezone

from gov import decision_codes
from gov import posture_cards
from gov.evidence import crosswalk

__all__ = [
    "ComplianceEmitterError",
    "emit",
    "emit_json",
    "emit_markdown",
    "emit_oscal",
    "source_content_digest",
    "validate_source",
]

OSCAL_VERSION = "1.1.3"
EXPORT_VERSION = "1.0.0"
FORMATS = ("oscal", "markdown", "json")
MAPPING_KINDS = ("code", "finding", "mechanism", "posture_track")
FINDING_STATUSES = ("open", "closed")

MALFORMED = "compliance-emitter-malformed"
UNLINKED_CLAIM = "compliance-emitter-unlinked-claim"
UNKNOWN_CODE = "compliance-emitter-unknown-code"
UNKNOWN_FINDING = "compliance-emitter-unknown-finding"
UNKNOWN_FORMAT = "compliance-emitter-unknown-format"
UNKNOWN_MECHANISM = "compliance-emitter-unknown-mechanism"
UNKNOWN_TRACK = "compliance-emitter-unknown-track"

_MAX_ID = 64
_MAX_TITLE = 200
_MAX_TEXT = 2000

# Fixed namespace so every UUID in an emitted package is deterministic.
_PACKAGE_NAMESPACE = uuid.UUID("4b7a2c19-8d3e-4f5a-9c1b-2e6d7f8a9b0c")


class ComplianceEmitterError(Exception):
    """Fail-closed compliance-emitter refusal carrying a taxonomy code."""

    def __init__(self, message, code):
        super().__init__(message)
        self.code = code


def _refuse(code, detail):
    raise ComplianceEmitterError("%s: %s" % (code, detail), code)


def _check_str(value, what, limit, code=MALFORMED):
    if not isinstance(value, str) or not value.strip() \
            or len(value) > limit:
        _refuse(code, "%s must be a non-empty string <= %d chars"
                % (what, limit))
    return value


def _uid(*parts):
    return str(uuid.uuid5(_PACKAGE_NAMESPACE, "\x00".join(parts)))


def _check_findings(findings):
    """Validate the deployment findings index; fail closed on misuse."""
    if findings is None:
        return None
    if not isinstance(findings, dict):
        _refuse(MALFORMED, "findings index must be a dict "
                "of finding_id -> open|closed")
    for fid, status in findings.items():
        _check_str(fid, "finding id", _MAX_ID)
        if status not in FINDING_STATUSES:
            _refuse(MALFORMED,
                    "finding %r has unknown status %r (want open|closed)"
                    % (fid, status))
    return findings


def _resolve_mapping(mapping, findings):
    """Validate one mapping against live evidence; return normalized."""
    if not isinstance(mapping, dict):
        _refuse(MALFORMED, "mapping must be a dict")
    kind = mapping.get("kind")
    if kind not in MAPPING_KINDS:
        _refuse(MALFORMED,
                "mapping kind %r not in %r" % (kind, MAPPING_KINDS))
    ref = _check_str(mapping.get("ref"), "mapping ref", _MAX_ID)
    rationale = _check_str(mapping.get("rationale"), "mapping rationale",
                           _MAX_TEXT)
    out = {"kind": kind, "ref": ref, "rationale": rationale}
    if kind == "code":
        if ref not in decision_codes.TAXONOMY:
            _refuse(UNKNOWN_CODE,
                    "decision code %r is not in the live taxonomy" % (ref,))
    elif kind == "mechanism":
        known = {m["id"] for m in crosswalk.MECHANISMS}
        if ref not in known:
            _refuse(UNKNOWN_MECHANISM,
                    "mechanism %r is not in the evidence crosswalk"
                    % (ref,))
    elif kind == "posture_track":
        if ref not in posture_cards.TRACKS:
            _refuse(UNKNOWN_TRACK,
                    "posture track %r is outside the closed track "
                    "vocabulary" % (ref,))
    else:  # kind == "finding"
        if findings is None or ref not in findings:
            _refuse(UNKNOWN_FINDING,
                    "finding %r is not in the deployment findings index"
                    % (ref,))
        out["finding_status"] = findings[ref]
    return out


def validate_source(source, findings=None):
    """Validate a control source; return a normalized deep copy.

    Raises ComplianceEmitterError (fail-closed) on any violation.
    """
    if not isinstance(source, dict):
        _refuse(MALFORMED, "control source must be a dict")
    findings = _check_findings(findings)
    cid = _check_str(source.get("id"), "control id", _MAX_ID)
    title = _check_str(source.get("title"), "control title", _MAX_TITLE)
    description = _check_str(source.get("description"),
                             "control description", _MAX_TEXT)
    mappings = source.get("mappings")
    if not isinstance(mappings, list) or len(mappings) == 0:
        _refuse(UNLINKED_CLAIM,
                "control %r has no evidence mappings; a claim with no "
                "evidence link is never emitted" % (cid,))
    normalized = {
        "id": cid,
        "title": title,
        "description": description,
        "mappings": [_resolve_mapping(m, findings) for m in mappings],
    }
    return normalized


def _canonical_bytes(payload):
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def source_content_digest(source, findings=None):
    """sha256 hex over the normalized source (+ resolved finding statuses).

    Binds the emitted artifacts to the exact source and evidence
    snapshot the emitter ran over: any drift in either changes the
    digest carried in every artifact's metadata.
    """
    normalized = validate_source(source, findings=findings)
    return hashlib.sha256(_canonical_bytes(normalized)).hexdigest()


_DISCLAIMER = (
    "This artifact is decision support for an auditor, not a "
    "certification claim and not legal advice. Emission proves the "
    "compliance emitter ran over the referenced Sasanam evidence; it "
    "does not re-verify that evidence -- a referenced decision code "
    "is a refusal path (not proof the deployment triggers it), a "
    "referenced mechanism is a claimed mapping (not proof the "
    "deployment runs it), and finding statuses come from the "
    "deployment-supplied index. OSCAL is a format, not a proof. "
    "Nothing here certifies compliance."
)


def _mapping_props(mapping):
    props = [
        {"name": "x-evidence-kind", "value": mapping["kind"]},
        {"name": "x-evidence-ref", "value": mapping["ref"]},
        {"name": "x-rationale", "value": mapping["rationale"]},
    ]
    if mapping["kind"] == "finding":
        props.append({"name": "x-finding-status",
                      "value": mapping["finding_status"]})
    return props


def emit_oscal(source, findings=None, generated_at=None):
    """OSCAL v1.1.x component-definition package for the control (dict)."""
    normalized = validate_source(source, findings=findings)
    digest = hashlib.sha256(
        _canonical_bytes(normalized)).hexdigest()
    cid = normalized["id"]
    reqs = []
    for i, mapping in enumerate(normalized["mappings"]):
        reqs.append({
            "uuid": _uid("implemented-requirement", cid, str(i)),
            "control-id": cid,
            "description": mapping["rationale"],
            "props": _mapping_props(mapping),
            "by-components": [{
                "component-uuid": _uid("component", cid),
                "uuid": _uid("by-component", cid, str(i)),
                "description": ("Traced to the %s evidence %r."
                                % (mapping["kind"], mapping["ref"])),
            }],
        })
    return {
        "component-definition": {
            "uuid": _uid("component-definition", cid),
            "metadata": {
                "title": "Compliance control %s "
                         "(OSCAL component-definition)" % (cid,),
                "last-modified": generated_at or datetime.now(
                    timezone.utc).isoformat(),
                "oscal-version": OSCAL_VERSION,
                "version": EXPORT_VERSION,
                "remarks": _DISCLAIMER,
                "props": [
                    {"name": "x-compliance-source-sha256", "value": digest},
                    {"name": "x-source",
                     "value": "control source %s" % (cid,)},
                    {"name": "x-export-module",
                     "value": "gov/compliance_emitter.py"},
                ],
            },
            "components": [{
                "uuid": _uid("component", cid),
                "type": "software",
                "title": normalized["title"],
                "description": normalized["description"],
                "props": [{"name": "x-control-id", "value": cid}],
                "control-implementations": [{
                    "uuid": _uid("control-implementation", cid),
                    "source": "sasanam-evidence",
                    "description": ("Evidence traceability for control %s "
                                    "against live Sasanam evidence."
                                    % (cid,)),
                    "implemented-requirements": reqs,
                }],
            }],
        }
    }


def emit_markdown(source, findings=None):
    """Human-readable compliance summary document (str)."""
    normalized = validate_source(source, findings=findings)
    digest = hashlib.sha256(
        _canonical_bytes(normalized)).hexdigest()
    cid = normalized["id"]
    lines = [
        "# Compliance control %s: %s" % (cid, normalized["title"]),
        "",
        normalized["description"],
        "",
        "Source digest: `%s`" % (digest,),
        "",
        "## Evidence traceability",
        "",
        "| # | kind | ref | status | rationale |",
        "|---|------|-----|--------|-----------|",
    ]
    for i, mapping in enumerate(normalized["mappings"], 1):
        status = mapping.get("finding_status", "live")
        lines.append("| %d | %s | `%s` | %s | %s |"
                     % (i, mapping["kind"], mapping["ref"], status,
                        mapping["rationale"]))
    lines += [
        "",
        "## Disclaimer",
        "",
        _DISCLAIMER,
        "",
    ]
    return "\n".join(lines)


def emit_json(source, findings=None):
    """Machine-readable canonical-JSON control mapping (str, deterministic).

    The JSON artifact states the honesty boundary per mapping: the
    emitter ran over the referenced evidence; it does not re-verify
    it.
    """
    normalized = validate_source(source, findings=findings)
    digest = hashlib.sha256(
        _canonical_bytes(normalized)).hexdigest()
    mappings = []
    for mapping in normalized["mappings"]:
        entry = {
            "kind": mapping["kind"],
            "ref": mapping["ref"],
            "rationale": mapping["rationale"],
            "verified_by_emitter": False,
            "emitter_note": ("emitter confirmed the ref exists in the "
                             "live evidence vocabulary; it did not "
                             "re-verify the evidence"),
        }
        if mapping["kind"] == "finding":
            entry["finding_status"] = mapping["finding_status"]
        mappings.append(entry)
    package = {
        "control": {
            "id": normalized["id"],
            "title": normalized["title"],
            "description": normalized["description"],
        },
        "mappings": mappings,
        "source_digest": digest,
        "disclaimer": _DISCLAIMER,
    }
    return json.dumps(package, sort_keys=True, indent=2,
                      ensure_ascii=True) + "\n"


def emit(source, fmt, findings=None, generated_at=None):
    """Dispatch over the closed format set {"oscal", "markdown", "json"}."""
    if fmt not in FORMATS:
        _refuse(UNKNOWN_FORMAT,
                "format %r not in %r" % (fmt, FORMATS))
    if fmt == "oscal":
        return emit_oscal(source, findings=findings,
                          generated_at=generated_at)
    if fmt == "markdown":
        return emit_markdown(source, findings=findings)
    return emit_json(source, findings=findings)
