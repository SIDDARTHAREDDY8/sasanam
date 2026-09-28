"""Evidence-index generator.

Scans a directory of live export artifacts and emits a deterministic
evidence-index document: which mechanisms are deployed, which controls
they evidence, and which concrete artifacts (with SHA-256 digests) back
each claim. JSON for machines, Markdown for humans.

Artifacts are RECOGNIZED, never invented: the scanner only picks up file
shapes it knows (see _SCANNERS); unknown files are listed under
"unrecognized" and never claimed as evidence. A mechanism with no found
artifacts is reported as "no artifacts found in this exports directory"
— the index never asserts evidence it cannot point at.

Determinism: directory scan order sorted, JSON emitted with sort_keys,
digests hex. Two runs over the same directory produce byte-identical
JSON (the eval battery pins this).
"""

import hashlib
import json
import os
from datetime import datetime, timezone

from .crosswalk import CONTROL_REGISTRY, MECHANISMS

__all__ = ["generate_evidence_index", "render_index_markdown",
           "KNOWN_FILE_SHAPES"]


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _count_lines(path):
    n = 0
    with open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def _scan_amsb_scorecard(path):
    """Parse a scorecard JSON; return summary facts or an error note."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            d = json.load(f)
    except (OSError, ValueError) as e:
        return {"parse": "failed", "error": str(e)}
    out = {}
    for k in ("benchmark", "grade", "uncapped_grade", "ceiling",
              "score", "defense_rate_pct", "false_positive_rate_pct",
              "critical_breaches", "generated_at", "determinism_rounds"):
        if k in d:
            out[k] = d[k]
    if isinstance(out.get("critical_breaches"), list):
        out["critical_breach_count"] = len(out["critical_breaches"])
    return out


def _scan_jsonl(path):
    return {"entries": _count_lines(path)}


def _scan_dir(path):
    names = sorted(os.listdir(path))
    return {"files": names, "file_count": len(names)}


# filename-shape -> (artifact_kind, scanner). Shapes are matched against
# the file NAME only (deterministic, no content sniffing beyond the
# kind's own parser).
KNOWN_FILE_SHAPES = (
    ("scorecard-*.json", "amsb_scorecard", _scan_amsb_scorecard),
    ("*.jsonl", "chained_ledger", _scan_jsonl),
)


def _match_shape(name):
    import fnmatch
    for shape, kind, scanner in KNOWN_FILE_SHAPES:
        if fnmatch.fnmatch(name, shape):
            return kind, scanner
    return None


def _scan_exports(exports_dir):
    found, unrecognized = [], []
    try:
        names = sorted(os.listdir(exports_dir))
    except OSError:
        return found, unrecognized
    for name in names:
        path = os.path.join(exports_dir, name)
        if os.path.isdir(path):
            if name.startswith("incident_export"):
                found.append({
                    "path": name,
                    "artifact_kind": "incident_export",
                    "sha256": None,
                    "summary": _scan_dir(path),
                })
            elif name.startswith("offline_bundle"):
                found.append({
                    "path": name,
                    "artifact_kind": "offline_bundle",
                    "sha256": None,
                    "summary": _scan_dir(path),
                })
            else:
                unrecognized.append(name)
            continue
        matched = _match_shape(name)
        if matched is None:
            if name.startswith("policy_export"):
                found.append({
                    "path": name,
                    "artifact_kind": "policy_export",
                    "sha256": _sha256_file(path),
                    "summary": {},
                })
            else:
                unrecognized.append(name)
            continue
        kind, scanner = matched
        try:
            summary = scanner(path)
        except OSError as e:
            summary = {"scan": "failed", "error": str(e)}
        found.append({
            "path": name,
            "artifact_kind": kind,
            "sha256": _sha256_file(path),
            "summary": summary,
        })
    return found, sorted(unrecognized)


def generate_evidence_index(exports_dir, generated_by="evidence-matrix lane",
                           generated_at=None):
    """Build the evidence-index document from a directory of exports.

    generated_at overrides the timestamp (for reproducible fixtures /
    byte-identical test comparisons); defaults to now (UTC)."""
    found, unrecognized = _scan_exports(exports_dir)
    by_kind = {}
    for a in found:
        by_kind.setdefault(a["artifact_kind"], []).append(a)

    mechanisms = []
    verified_count = 0
    unverified_count = 0
    for m in MECHANISMS:
        rows = []
        for (fw, cid, detail) in m["controls"]:
            reg = CONTROL_REGISTRY["%s:%s" % (fw, cid)]
            status = detail["mapping_status"]
            if status == "verified":
                verified_count += 1
            else:
                unverified_count += 1
            rows.append({
                "framework": fw,
                "control_id": cid,
                "control_title": reg["title"],
                "mapping_status": status,
                "verification_note": detail["verification_note"],
                "rationale": detail["rationale"],
                "residual": detail["residual"],
            })
        artifacts = []
        for kind in m["exports"]:
            artifacts.extend(by_kind.get(kind, []))
        mechanisms.append({
            "mechanism_id": m["id"],
            "mechanism_name": m["name"],
            "deployment_status": m["deployment_status"],
            "description": m["description"],
            "implementation": list(m["implementation"]),
            "controls": rows,
            "artifacts_found": artifacts,
            "evidence_present": bool(artifacts),
        })

    return {
        "document": "evidence-index",
        "version": 1,
        "generated_at": generated_at or datetime.now(timezone.utc).isoformat(),
        "generated_by": generated_by,
        "exports_dir": os.path.abspath(exports_dir),
        "summary": {
            "mechanisms": len(mechanisms),
            "mechanisms_with_artifacts": sum(
                1 for x in mechanisms if x["evidence_present"]),
            "control_mappings": verified_count + unverified_count,
            "verified_mappings": verified_count,
            "unverified_mappings": unverified_count,
            "artifacts_found": len(found),
            "unrecognized_files": len(unrecognized),
        },
        "mechanisms": mechanisms,
        "unrecognized_files": unrecognized,
        "disclaimer": (
            "This index is decision support for an auditor, not a "
            "certification claim and not legal advice. 'verified' control "
            "citations were checked against the primary source text; "
            "'unverified' citations (ISO/IEC 42001:2023 — a licensed "
            "standard) were cross-checked across secondary reproductions "
            "and must be confirmed against the licensed text. Mechanisms "
            "with no artifacts found in the exports directory carry no "
            "evidence claim in this index."),
    }


def render_index_markdown(index):
    """Human-readable rendering of an evidence-index document."""
    L = []
    L.append("# Evidence index")
    L.append("")
    L.append("Generated: %s" % index["generated_at"])
    L.append("Generated by: %s" % index["generated_by"])
    L.append("")
    s = index["summary"]
    L.append("## Summary")
    L.append("")
    L.append("- Mechanisms indexed: %d (%d with artifacts found)" % (
        s["mechanisms"], s["mechanisms_with_artifacts"]))
    L.append("- Control mappings: %d (%d verified, %d unverified)" % (
        s["control_mappings"], s["verified_mappings"],
        s["unverified_mappings"]))
    L.append("- Artifacts found: %d; unrecognized files: %d" % (
        s["artifacts_found"], s["unrecognized_files"]))
    L.append("")
    for m in index["mechanisms"]:
        L.append("## %s" % m["mechanism_name"])
        L.append("")
        L.append("Status: %s" % m["deployment_status"])
        L.append("")
        L.append(m["description"])
        L.append("")
        L.append("Implementation: %s" % ", ".join(
            "`%s`" % i for i in m["implementation"]))
        L.append("")
        if m["artifacts_found"]:
            L.append("### Artifacts")
            L.append("")
            for a in m["artifacts_found"]:
                digest = a["sha256"] or "(directory)"
                L.append("- `%s` [%s] sha256:`%s`" % (
                    a["path"], a["artifact_kind"], digest))
            L.append("")
        else:
            L.append("No artifacts found in the exports directory — "
                     "no evidence claim is made for this mechanism here.")
            L.append("")
        L.append("### Controls evidenced")
        L.append("")
        for c in m["controls"]:
            L.append("- **%s %s** (%s)" % (
                c["framework"], c["control_id"], c["mapping_status"]))
            L.append("  - %s" % c["control_title"])
            L.append("  - Why: %s" % c["rationale"])
            L.append("  - Residual: %s" % c["residual"])
        L.append("")
    if index["unrecognized_files"]:
        L.append("## Unrecognized files (not claimed as evidence)")
        L.append("")
        for n in index["unrecognized_files"]:
            L.append("- `%s`" % n)
        L.append("")
    L.append("## Disclaimer")
    L.append("")
    L.append(index["disclaimer"])
    L.append("")
    return "\n".join(L)
