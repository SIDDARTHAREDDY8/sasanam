"""Evidence-matrix structural-integrity battery.

Stdlib only, deterministic, no network. Pins the honest-design rules of
the evidence index:

  1. Every mechanism maps to >= 1 VERIFIED control (no unverified-only rows).
  2. Every cited control ID is in CONTROL_REGISTRY (invented IDs fail).
  3. Every ISO/IEC 42001 citation is marked "unverified" with the
     licensed-text caveat (honesty pin).
  4. evidence_checklist returns the full contract schema for a known
     control and raises UnknownControlError for invented controls.
  5. Checklist system_artifacts resolve only to known export artifact kinds.
  6. Inversion consistency: mechanisms_for_control inverts
     controls_for_mechanism.
  7. Golden sample: fixture exports -> generate index -> schema asserts;
     byte-identical across two runs (determinism pin).

Run:  env -u GOV_DEPLOYMENT_MODE ~/workspace/.gov-venv/bin/python \
        evals/evidence_matrix_battery.py
"""
import os
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import sys
import tempfile

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from gov.evidence import (  # noqa: E402
    CONTROL_REGISTRY,
    KNOWN_ARTIFACT_KINDS,
    MECHANISMS,
    UnknownControlError,
    controls_for_mechanism,
    evidence_checklist,
    generate_evidence_index,
    mechanisms_for_control,
    render_index_markdown,
)
from gov.evidence.checklist import checklist_schema_keys  # noqa: E402

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, PASS if cond else FAIL, detail))
    return bool(cond)


def t_every_mechanism_has_verified_control():
    ok = True
    for m in MECHANISMS:
        verified = [c for c in controls_for_mechanism(m["id"])
                    if c["mapping_status"] == "verified"]
        ok &= check("mechanism %s has >=1 verified control" % m["id"],
                    len(verified) >= 1,
                    "verified=%d" % len(verified))
    return ok


def t_no_invented_control_ids():
    ok = True
    for m in MECHANISMS:
        for (fw, cid, _detail) in m["controls"]:
            key = "%s:%s" % (fw, cid)
            ok &= check("control %s registered" % key, key in CONTROL_REGISTRY)
    return ok


def t_iso_always_unverified():
    ok = True
    for m in MECHANISMS:
        for c in controls_for_mechanism(m["id"]):
            if c["framework"] == "ISO-IEC-42001-2023":
                ok &= check(
                    "ISO %s marked unverified" % c["control_id"],
                    c["mapping_status"] == "unverified"
                    and "licensed" in c["verification_note"].lower(),
                    c["verification_note"][:60])
    # and the registry agrees
    for key, reg in CONTROL_REGISTRY.items():
        if key.startswith("ISO-IEC-42001-2023:"):
            ok &= check("registry %s unverified" % key,
                        reg["status"] == "unverified")
    return ok


def t_checklist_schema_and_unknown_control():
    ok = True
    cl = evidence_checklist("NIST-AI-RMF-1.0", "MEASURE 2.1")
    ok &= check("checklist has all schema keys",
                all(k in cl for k in checklist_schema_keys),
                ",".join(sorted(cl.keys())))
    ok &= check("checklist control block marked verified",
                cl["control"]["mapping_status"] == "verified")
    ok &= check("checklist has evidence classes",
                all(cl[k] for k in ("documents", "records",
                                   "system_artifacts", "interviews")))
    ok &= check("checklist has why/questions/failures/sampling",
                all(cl[k] for k in ("why", "likely_auditor_questions",
                                    "common_failure_modes",
                                    "sampling_guidance")))
    try:
        evidence_checklist("NIST-AI-RMF-1.0", "MEASURE 9.9")
        ok &= check("invented control raises UnknownControlError", False)
    except UnknownControlError:
        ok &= check("invented control raises UnknownControlError", True)
    try:
        evidence_checklist("MADE-UP-FRAMEWORK", "X.1")
        ok &= check("invented framework raises UnknownControlError", False)
    except UnknownControlError:
        ok &= check("invented framework raises UnknownControlError", True)
    # ISO checklist carries the caveat through
    cl_iso = evidence_checklist("ISO-IEC-42001-2023", "A.6.2.6")
    ok &= check("ISO checklist carries unverified caveat",
                cl_iso["control"]["mapping_status"] == "unverified"
                and "licensed" in cl_iso["control"]["verification_note"].lower())
    return ok


def t_checklist_artifacts_resolve():
    ok = True
    for key in CONTROL_REGISTRY:
        fw, cid = key.split(":", 1)
        try:
            cl = evidence_checklist(fw, cid)
        except UnknownControlError:
            ok &= check("checklist exists for %s" % key, False)
            continue
        for a in cl["system_artifacts"]:
            ok &= check("artifact kind %s known (%s)" % (
                a["artifact_kind"], key),
                a["artifact_kind"] in KNOWN_ARTIFACT_KINDS)
        mechs = {m["mechanism_id"] for m in
                 mechanisms_for_control(fw, cid)}
        art_mechs = {a["mechanism"] for a in cl["system_artifacts"]}
        ok &= check("checklist artifacts agree with crosswalk (%s)" % key,
                    art_mechs <= mechs,
                    "extra=%s" % sorted(art_mechs - mechs))
    return ok


def t_inversion_consistency():
    ok = True
    for m in MECHANISMS:
        for c in controls_for_mechanism(m["id"]):
            inv = mechanisms_for_control(c["framework"], c["control_id"])
            ids = [x["mechanism_id"] for x in inv]
            ok &= check("inversion round-trips %s/%s" % (
                c["framework"], c["control_id"]),
                m["id"] in ids)
    try:
        mechanisms_for_control("NIST-AI-RMF-1.0", "MEASURE 9.9")
        ok &= check("inversion rejects invented control", False)
    except KeyError:
        ok &= check("inversion rejects invented control", True)
    return ok


def _fixture_exports(tmp):
    d = os.path.join(tmp, "exports")
    os.makedirs(d)
    # amsb scorecard fixture (shape of the real scorecard JSON)
    scorecard = {
        "benchmark": "amsb",
        "grade": "C",
        "uncapped_grade": "B",
        "ceiling": "C",
        "score": 88.89,
        "defense_rate_pct": 100.0,
        "false_positive_rate_pct": 0.0,
        "critical_breaches": ["a1-default-off"],
        "generated_at": "2026-09-28T09:17:22Z",
        "determinism_rounds": 3,
    }
    with open(os.path.join(d, "scorecard-20260928T091722Z.json"), "w",
               encoding="utf-8") as f:
        json.dump(scorecard, f, sort_keys=True, indent=2)
    # chained ledger fixture
    with open(os.path.join(d, "audit_log.jsonl"), "w",
              encoding="utf-8") as f:
        for i in range(5):
            f.write(json.dumps({"seq": i, "event": "test"}) + "\n")
    # incident export fixture dir
    ie = os.path.join(d, "incident_export_2026-09-28")
    os.makedirs(ie)
    with open(os.path.join(ie, "incident.json"), "w",
              encoding="utf-8") as f:
        json.dump({"incident": "fixture"}, f)
    # a file the scanner must NOT claim
    with open(os.path.join(d, "notes.txt"), "w",
              encoding="utf-8") as f:
        f.write("not evidence\n")
    return d


def t_golden_sample():
    ok = True
    with tempfile.TemporaryDirectory(prefix="evidx-") as tmp:
        d = _fixture_exports(tmp)
        idx1 = generate_evidence_index(d, generated_by="battery",
                                       generated_at="2026-09-28T00:00:00+00:00")
        idx2 = generate_evidence_index(d, generated_by="battery",
                                       generated_at="2026-09-28T00:00:00+00:00")
        j1 = json.dumps(idx1, sort_keys=True, indent=2)
        j2 = json.dumps(idx2, sort_keys=True, indent=2)
        ok &= check("index deterministic across runs", j1 == j2)
        ok &= check("index document/version keys",
                    idx1["document"] == "evidence-index"
                    and idx1["version"] == 1)
        mechs = {m["mechanism_id"]: m for m in idx1["mechanisms"]}
        ok &= check("all mechanisms indexed",
                    set(mechs) == {m["id"] for m in MECHANISMS})
        amsb = mechs["amsb-scorecards"]
        ok &= check("scorecard artifact found",
                    any(a["artifact_kind"] == "amsb_scorecard"
                        for a in amsb["artifacts_found"]))
        ok &= check("scorecard summary parsed",
                    any(a["summary"].get("grade") == "C"
                        for a in amsb["artifacts_found"]
                        if a["artifact_kind"] == "amsb_scorecard"))
        ok &= check("unrecognized file not claimed",
                    "notes.txt" in idx1["unrecognized_files"])
        ok &= check("disclaimer present",
                    "not a" in idx1["disclaimer"]
                    and "certification" in idx1["disclaimer"])
        md = render_index_markdown(idx1)
        ok &= check("markdown renders mechanisms and disclaimer",
                    "# Evidence index" in md
                    and "## Disclaimer" in md
                    and "a2a" in md.lower())
    return ok


def t_mechanism_row_integrity():
    ok = True
    ids = [m["id"] for m in MECHANISMS]
    ok &= check("mechanism ids unique", len(ids) == len(set(ids)))
    for m in MECHANISMS:
        ok &= check("mechanism %s has description/impl/exports" % m["id"],
                    bool(m["description"]) and bool(m["implementation"])
                    and bool(m["exports"]))
        for kind in m["exports"]:
            ok &= check("mechanism %s export kind known" % m["id"],
                        kind in KNOWN_ARTIFACT_KINDS, kind)
        ok &= check("mechanism %s deployment_status set" % m["id"],
                    m["deployment_status"] in ("shipped", "shipped-partial",
                                               "in-flight"))
    return ok


TESTS = [
    t_every_mechanism_has_verified_control,
    t_no_invented_control_ids,
    t_iso_always_unverified,
    t_checklist_schema_and_unknown_control,
    t_checklist_artifacts_resolve,
    t_inversion_consistency,
    t_golden_sample,
    t_mechanism_row_integrity,
]


def main():
    for t in TESTS:
        try:
            t()
        except Exception as e:  # noqa: BLE001 - battery must not die mid-run
            check(t.__name__, False, "EXC %r" % (e,))
    npass = sum(1 for _, s, _ in results if s == PASS)
    nfail = len(results) - npass
    print("evidence-matrix battery: %d/%d checks passed" % (npass, len(results)))
    for name, status, detail in results:
        if status == FAIL:
            print("  FAIL %s %s" % (name, detail))
    return 0 if nfail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
