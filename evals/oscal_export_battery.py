"""OSCAL export battery (wave-174 lane 3).

Red-first: FAILS on the unmodified tree with
  ModuleNotFoundError: gov.evidence.oscal_export
(documented failure mode — the export seam does not exist there).
On the built tree, pins:

  1. Determinism: two generations with fixed generated_at are
     byte-identical; different generated_at differ only in last-modified.
  2. Completeness + traceability: every MECHANISMS row appears as a
     component; every crosswalk (mechanism, framework, control_id)
     mapping appears as an implemented-requirement; every exported
     (framework, control_id) is in CONTROL_REGISTRY (invented IDs fail).
  3. Unverified stays unverified: every ISO/IEC 42001:2023 mapping
     carries mapping-status=unverified with the licensed-text caveat;
     no mapping is presented as verified unless the crosswalk says so.
  4. OSCAL v1.1.x schema shape: required fields present
     (component-definition.uuid, metadata.title/last-modified/
     oscal-version/version, component uuid/type/title/description,
     control-implementation uuid/source/implemented-requirements,
     implemented-requirement uuid/control-id); UUIDs parse; control-ids
     match the registry citation format.
  5. Content binding: the package carries a crosswalk content digest;
     the digest is sensitive to content (flipping one description byte
     changes it); the embedded digest equals the digest recomputed from
     the live crosswalk through the module's documented helper.
  6. Honest disclaimer: metadata.remarks carries the
     decision-support-not-certification language.

Stdlib only, deterministic, no network. Depth-1 green check honoring
GOV_SKIP_GREEN (runs the evidence-matrix battery as the adjacent
canary, since this export is derived from its crosswalk).
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import json
import sys
import uuid as _uuid

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

PASS, FAIL = "PASS", "FAIL"
results = []


def check(name, cond, detail=""):
    results.append((name, PASS if cond else FAIL, detail))
    return bool(cond)


def main():
    try:
        from gov.evidence import oscal_export  # noqa: E402
        from gov.evidence import (  # noqa: E402
            CONTROL_REGISTRY,
            FRAMEWORKS,
            MECHANISMS,
            controls_for_mechanism,
        )
    except ImportError as e:
        results.append(("oscal_export seam importable", FAIL, str(e)))
        return report(1)

    T0 = "2026-09-28T12:00:00+00:00"

    # 1. Determinism.
    a = oscal_export.component_definition_json(generated_at=T0)
    b = oscal_export.component_definition_json(generated_at=T0)
    check("byte-identical x2 (fixed generated_at)", a == b,
          "len=%d" % len(a))
    c = oscal_export.component_definition_json(
        generated_at="2026-09-28T12:00:01+00:00")
    check("different generated_at differs", a != c)
    da, dc = (json.loads(a)["component-definition"]["metadata"]["last-modified"],
              json.loads(c)["component-definition"]["metadata"]["last-modified"])
    check("only last-modified differs across timestamps",
          da != dc and
          json.loads(a)["component-definition"]["components"] ==
          json.loads(c)["component-definition"]["components"])

    pkg = json.loads(a)["component-definition"]

    # 4. OSCAL v1.1.x schema shape (required fields).
    check("oscal-version present", pkg["metadata"].get("oscal-version", "").startswith("1.1."),
          pkg["metadata"].get("oscal-version"))
    for f in ("uuid", "metadata"):
        check("component-definition.%s present" % f, f in pkg)
    md = pkg["metadata"]
    for f in ("title", "last-modified", "oscal-version", "version"):
        check("metadata.%s present" % f, bool(md.get(f)), repr(md.get(f)))
    try:
        _uuid.UUID(pkg["uuid"])
        uuid_ok = True
    except ValueError:
        uuid_ok = False
    check("component-definition.uuid parses", uuid_ok, pkg["uuid"][:8] + "...")

    comps = pkg["components"]
    check("component count == MECHANISMS count",
          len(comps) == len(MECHANISMS), "%d vs %d" % (len(comps), len(MECHANISMS)))
    comp_by_id = {}
    for comp in comps:
        ok = all(comp.get(f) for f in ("uuid", "type", "title", "description"))
        check("component shape (%s)" % comp.get("uuid", "?")[:8], ok)
        try:
            _uuid.UUID(comp["uuid"]); uok = True
        except ValueError:
            uok = False
        check("component uuid parses", uok)
        mid = comp.get("props", [{}])
        mech_id = next((p.get("value") for p in comp.get("props", [])
                        if p.get("name") == "x-mechanism-id"), None)
        check("component carries x-mechanism-id", mech_id is not None)
        if mech_id:
            comp_by_id[mech_id] = comp
        for ci in comp.get("control-implementations", []):
            check("control-implementation uuid+source+reqs",
                  all([ci.get("uuid"), ci.get("source"),
                       isinstance(ci.get("implemented-requirements"), list)]))
            check("control-implementation.source is a known framework",
                  ci.get("source") in FRAMEWORKS, repr(ci.get("source")))
            for ir in ci["implemented-requirements"]:
                check("implemented-requirement uuid+control-id",
                      all([ir.get("uuid"), ir.get("control-id")]))
                reg_key = "%s:%s" % (ci["source"], ir["control-id"])
                check("exported control in CONTROL_REGISTRY (%s)" % reg_key,
                      reg_key in CONTROL_REGISTRY)

    # 2. Completeness + traceability: every crosswalk mapping exported.
    exported = {}
    for mid, comp in comp_by_id.items():
        for ci in comp.get("control-implementations", []):
            for ir in ci["implemented-requirements"]:
                exported[(mid, ci["source"], ir["control-id"])] = ir
    expected = set()
    for m in MECHANISMS:
        for (fw, cid, detail) in m["controls"]:
            expected.add((m["id"], fw, cid))
    check("no dropped mappings", expected <= set(exported.keys()),
          "missing=%r" % sorted(expected - set(exported.keys()))[:3])
    check("no invented mappings", set(exported.keys()) <= expected,
          "extra=%r" % sorted(set(exported.keys()) - expected)[:3])
    check("every mechanism exported", set(comp_by_id.keys()) ==
          {m["id"] for m in MECHANISMS})

    # Round-trip content fidelity: rationale/residual/verification_note
    # match the crosswalk verbatim (the crosswalk is the source of truth).
    fidelity_ok = True
    for m in MECHANISMS:
        rows = {(c["framework"], c["control_id"]): c
                for c in controls_for_mechanism(m["id"])}
        for key, ir in exported.items():
            if key[0] != m["id"]:
                continue
            src = rows.get((key[1], key[2]))
            props = {p["name"]: p["value"] for p in ir.get("props", [])}
            if (src is None or props.get("x-rationale") != src["rationale"]
                    or props.get("x-residual") != src["residual"]
                    or props.get("x-verification-note") != src["verification_note"]
                    or props.get("mapping-status") != src["mapping_status"]):
                fidelity_ok = False
    check("round-trip fidelity vs crosswalk (rationale/residual/note/status)",
          fidelity_ok)

    # 3. Unverified stays unverified.
    unver_ok = True
    verified_ok = True
    for (mid, fw, cid), ir in exported.items():
        props = {p["name"]: p["value"] for p in ir.get("props", [])}
        src = next((c for c in controls_for_mechanism(mid)
                    if c["framework"] == fw and c["control_id"] == cid), None)
        if fw == "ISO-IEC-42001-2023":
            if props.get("mapping-status") != "unverified":
                unver_ok = False
            if "licensed" not in props.get("x-verification-note", "").lower():
                unver_ok = False
        if src and props.get("mapping-status") != src["mapping_status"]:
            verified_ok = False
    check("ISO mappings stay unverified with licensed-text caveat", unver_ok)
    check("mapping-status matches crosswalk for every row", verified_ok)

    # 5. Content binding: digest sensitive to content, embedded == recomputed.
    live_digest = oscal_export.crosswalk_content_digest()
    check("digest is 64 hex chars",
          len(live_digest) == 64 and all(x in "0123456789abcdef" for x in live_digest),
          live_digest[:16] + "...")
    mutated = json.loads(json.dumps(MECHANISMS))
    mutated[0]["description"] = mutated[0]["description"] + " "
    mutated_digest = oscal_export._canonical_crosswalk_bytes(
        mutated, CONTROL_REGISTRY, FRAMEWORKS)
    import hashlib
    mutated_hex = hashlib.sha256(mutated_digest).hexdigest()
    check("digest sensitive to one-byte content change",
          mutated_hex != live_digest)
    embedded = None
    for p in md.get("props", []):
        if p.get("name") == "x-crosswalk-sha256":
            embedded = p.get("value")
    check("embedded digest == recomputed digest", embedded == live_digest,
          "embedded=%r" % (embedded or "")[:16])

    # 6. Honest disclaimer in metadata remarks.
    remarks = (md.get("remarks") or "").lower()
    check("disclaimer: decision support, not certification",
          "not a certification" in remarks or "not certification" in remarks,
          remarks[:60])
    check("disclaimer: unverified ISO caveat",
          "42001" in remarks and "licensed" in remarks, remarks[:60])

    return report(0)


def green_check():
    """Depth-1 green check: run the adjacent evidence-matrix battery.

    Honors GOV_SKIP_GREEN=1 (a parent's green check sets it; this
    battery then records a skip instead of spawning). Never spawns
    another battery's full main without that guard.
    """
    import subprocess
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        print("green check skipped (GOV_SKIP_GREEN=1)")
        return 0
    battery = os.path.join(REPO_ROOT, "evals", "evidence_matrix_battery.py")
    print("green check: running %s" % battery)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    r = subprocess.run([sys.executable, battery], env=env,
                       capture_output=True, text=True, timeout=600)
    tail = (r.stdout + r.stderr).strip().splitlines()[-3:]
    for line in tail:
        print("  | " + line)
    return r.returncode


def report(code):
    print("---")
    fails = [r for r in results if r[1] == FAIL]
    for name, status, detail in results:
        print("%s %-58s %s" % (status, name, detail))
    print("---")
    print("%d/%d PASS" % (len(results) - len(fails), len(results)))
    if fails:
        print("RED")
        return 1
    print("GREEN")
    return code


if __name__ == "__main__":
    code = main()
    if code == 0:
        code = green_check()
    sys.exit(code)
