"""Break-first red battery: evidence-graph projection over bundles,
skills, and decisions (wave-250 lane 4; guacsec/guac ADAPT).

The gap under test: evidence exists as separate artifacts (offline
bundles, DSSE envelopes, skill admission records, decision packets) but
the tree ships NO unified auditor traversal -- "show me everything
about this skill/decision" requires manual assembly across modules.

On the pristine wave-249 base every probe reports GAP (the module does
not exist / has no traversal). After the build, every probe must report
HELD under both staging and a clean environment.

Synthetic/local only. Deterministic: fixed seeds, no wall clock in
asserted values, sorted assertions. Stdlib only, no in-repo git
subprocesses. Fresh TMPDIR per process is the caller's concern; this
battery writes nothing outside the stdlib tempdir.
"""

import hashlib
import json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

# ------------------------------------------------------------------
# probe harness
# ------------------------------------------------------------------

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def load_graph_module():
    """Return (gov.evidence_graph, None) or (None, reason)."""
    try:
        from gov import evidence_graph
        return evidence_graph, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


def _keys():
    """Deterministic ed25519 material (synthetic)."""
    from gov import ed25519
    auth_seed = b"\x11" * 32
    step_seed = b"\x22" * 32
    return {
        "auth_seed": auth_seed,
        "step_seed": step_seed,
        "auth_pub": ed25519.publickey(auth_seed).hex(),
        "step_pub": ed25519.publickey(step_seed).hex(),
    }


def _admit_skill():
    """Admit a synthetic skill; returns (verdict, keys)."""
    from gov import skill_admission
    keys = _keys()
    rules = [("REQUIRE", "skill-src.zip"),
             ("MATCH", "skill.tar.gz", "ab" * 32),
             ("DISALLOW",)]
    layout = skill_admission.make_layout(
        "layout-graph-1",
        [{"name": "build", "command": ["make", "bundle"],
          "signer_pub": keys["step_pub"], "rules": rules}],
        keys["auth_seed"])
    link = skill_admission.make_link(
        "layout-graph-1", "build", ["make", "bundle"],
        {"skill-src.zip": "ab" * 32}, {"skill.tar.gz": "ab" * 32},
        keys["step_seed"])
    verdict = skill_admission.admit(
        layout, [link], keys["auth_pub"])
    assert verdict["admitted"] is True, verdict
    return verdict, keys


def _fake_manifest(bundle_id):
    """Minimal offline-bundle manifest shape for projection."""
    return {
        "bundle_id": bundle_id,
        "bundle_format": "offline-evidence-bundle/1.0",
        "ledger_digest": "ab" * 32,
        "window": {"from_seq": 1, "to_seq": 3},
        "entries": [
            {"seq": 1, "digest": "01" * 32},
            {"seq": 2, "digest": "02" * 32},
            {"seq": 3, "digest": "03" * 32},
        ],
    }


def probe_01_importable():
    mod, reason = load_graph_module()
    if mod is None:
        return _record("import-importable", "GAP", reason)
    for name in ("EvidenceGraph", "traverse", "provenance",
                 "blast_radius", "project_admission",
                 "project_bundle_manifest", "project_decision_packet",
                 "project_policy_revision", "project_revocation"):
        if not hasattr(mod, name):
            return _record("import-importable", "GAP",
                           "missing export: " + name)
    return _record("import-importable", "HELD")


def probe_02_skill_admission_projection():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("skill-admission-projection", "GAP",
                       "gov.evidence_graph missing")
    verdict, keys = _admit_skill()
    g = mod.EvidenceGraph()
    mod.project_admission(g, verdict, authority_id=keys["auth_pub"])
    skill = "skill:layout-graph-1"
    assert skill in g.traverse(skill), "skill node missing"
    reached = g.traverse(skill)
    assert any(n == "identity:" + keys["auth_pub"] for n in reached), \
        "admitted_by edge to authority identity missing: %r" % (reached,)
    return _record("skill-admission-projection", "HELD")


def probe_03_bundle_projection():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("bundle-projection", "GAP",
                       "gov.evidence_graph missing")
    g = mod.EvidenceGraph()
    mod.project_bundle_manifest(g, _fake_manifest("bundle-xyz"))
    reached = g.traverse("bundle:bundle-xyz")
    assert "bundle:bundle-xyz" in reached, reached
    # three sealed entries -> three sealed_in edges
    sealed = [n for n in reached if n.startswith("record:")]
    assert len(sealed) == 3, "expected 3 sealed records: %r" % (reached,)
    return _record("bundle-projection", "HELD")


def probe_04_decision_projection():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("decision-projection", "GAP",
                       "gov.evidence_graph missing")
    g = mod.EvidenceGraph()
    packet = {"decision": "allow", "policy_id": "pol-1",
              "skill_id": "layout-graph-1", "seq": 7}
    node = mod.project_decision_packet(
        g, packet, identity_id="agent-7", skill_id="layout-graph-1")
    assert node.startswith("decision:"), node
    reached = g.traverse(node)
    assert "identity:agent-7" in reached, reached
    assert "skill:layout-graph-1" in reached, reached
    return _record("decision-projection", "HELD")


def probe_05_traverse_unified():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("traverse-unified", "GAP",
                       "gov.evidence_graph missing")
    verdict, keys = _admit_skill()
    g = mod.EvidenceGraph()
    mod.project_admission(g, verdict, authority_id=keys["auth_pub"])
    packet = {"decision": "allow", "policy_id": "pol-1",
              "skill_id": "layout-graph-1", "seq": 7}
    decision = mod.project_decision_packet(
        g, packet, identity_id="agent-7", skill_id="layout-graph-1")
    manifest = _fake_manifest("bundle-xyz")
    mod.project_bundle_manifest(g, manifest,
                                record_nodes=[decision])
    # one unified walk from the skill reaches the decision AND bundle
    reached = g.traverse("skill:layout-graph-1")
    assert decision in reached, "decision not reachable from skill"
    assert "bundle:bundle-xyz" in reached, \
        "bundle not reachable from skill: %r" % (reached,)
    return _record("traverse-unified", "HELD")


def probe_06_provenance_chain():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("provenance-chain", "GAP",
                       "gov.evidence_graph missing")
    verdict, keys = _admit_skill()
    g = mod.EvidenceGraph()
    mod.project_admission(g, verdict, authority_id=keys["auth_pub"])
    packet = {"decision": "allow", "policy_id": "pol-1",
              "skill_id": "layout-graph-1", "seq": 7}
    decision = mod.project_decision_packet(
        g, packet, identity_id="agent-7", skill_id="layout-graph-1")
    chain = mod.provenance(g, decision)
    flat = [n for path in chain for n in path]
    # the chain must reach back to the skill admission authority
    assert "identity:" + keys["auth_pub"] in flat, \
        "admission authority not in provenance: %r" % (chain,)
    assert "skill:layout-graph-1" in flat, chain
    assert chain[0][0] == decision, chain
    return _record("provenance-chain", "HELD")


def probe_07_blast_radius():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("blast-radius", "GAP", "gov.evidence_graph missing")
    verdict, keys = _admit_skill()
    g = mod.EvidenceGraph()
    mod.project_admission(g, verdict, authority_id=keys["auth_pub"])
    packet = {"decision": "allow", "policy_id": "pol-1",
              "skill_id": "layout-graph-1", "seq": 7}
    decision = mod.project_decision_packet(
        g, packet, identity_id="agent-7", skill_id="layout-graph-1")
    radius = mod.blast_radius(g, "skill:layout-graph-1")
    assert decision in radius, \
        "dependent decision missing from blast radius: %r" % (radius,)
    assert "skill:layout-graph-1" in radius, radius
    return _record("blast-radius", "HELD")


def probe_08_ambiguous_link_refused():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("ambiguous-link-refused", "GAP",
                       "gov.evidence_graph missing")
    g = mod.EvidenceGraph()
    g.add_identity("identity:agent-alpha")
    g.add_identity("identity:agent-alpine")
    g.add_node("skill:s1", "skill")
    try:
        g.link("skill:s1", "identity:agent-al", "produced_by")
    except mod.AmbiguousLink as exc:
        assert exc.code == "evidence-graph-ambiguous-link", exc.code
        return _record("ambiguous-link-refused", "HELD")
    return _record("ambiguous-link-refused", "GAP",
                   "ambiguous selector did not raise")


def probe_09_deterministic_digest():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("deterministic-digest", "GAP",
                       "gov.evidence_graph missing")
    verdict, keys = _admit_skill()

    def build(order):
        g = mod.EvidenceGraph()
        if order == 0:
            mod.project_admission(g, verdict, authority_id=keys["auth_pub"])
            mod.project_bundle_manifest(g, _fake_manifest("bundle-xyz"))
        else:
            mod.project_bundle_manifest(g, _fake_manifest("bundle-xyz"))
            mod.project_admission(g, verdict, authority_id=keys["auth_pub"])
        return g.digest()

    d1, d2 = build(0), build(1)
    assert d1 == d2, "insertion order changed graph digest"
    assert len(d1) == 64 and all(c in "0123456789abcdef" for c in d1), d1
    return _record("deterministic-digest", "HELD")


def probe_10_bounds_fail_closed():
    mod, _ = load_graph_module()
    if mod is None:
        return _record("bounds-fail-closed", "GAP",
                       "gov.evidence_graph missing")
    g = mod.EvidenceGraph(max_nodes=4, max_edges=4)
    for i in range(4):
        g.add_node("skill:s%d" % i, "skill")
    try:
        g.add_node("skill:overflow", "skill")
    except mod.GraphOverflow as exc:
        assert exc.code == "evidence-graph-overflow", exc.code
    else:
        return _record("bounds-fail-closed", "GAP",
                       "node overflow did not raise")
    try:
        g.add_edge("skill:s0", "skill:s1", "supersedes")
        g.add_edge("skill:s1", "skill:s2", "supersedes")
        g.add_edge("skill:s2", "skill:s3", "supersedes")
        g.add_edge("skill:s3", "skill:s0", "supersedes")
        g.add_edge("skill:s0", "skill:s2", "revokes")
    except mod.GraphOverflow as exc:
        assert exc.code == "evidence-graph-overflow", exc.code
        return _record("bounds-fail-closed", "HELD")
    return _record("bounds-fail-closed", "GAP", "edge overflow did not raise")


PROBES = (
    probe_01_importable,
    probe_02_skill_admission_projection,
    probe_03_bundle_projection,
    probe_04_decision_projection,
    probe_05_traverse_unified,
    probe_06_provenance_chain,
    probe_07_blast_radius,
    probe_08_ambiguous_link_refused,
    probe_09_deterministic_digest,
    probe_10_bounds_fail_closed,
)


def green_check():
    """Depth-1: adjacent batteries with GOV_SKIP_GREEN=1 in the child."""
    if SKIP_GREEN:
        return "skipped (GOV_SKIP_GREEN=1)"
    import subprocess
    import sys
    notes = []
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for battery in ("evals/w248_skill_admission_probes.py",
                    "evals/w249_wiring_probes.py"):
        path = os.path.join(repo, battery)
        if not os.path.exists(path):
            notes.append(battery + ": missing")
            continue
        env = dict(os.environ)
        env["GOV_SKIP_GREEN"] = "1"
        proc = subprocess.run(
            [sys.executable, path], env=env, capture_output=True,
            text=True, timeout=600, cwd=repo)
        notes.append("%s: rc=%d" % (battery, proc.returncode))
        if proc.returncode != 0:
            raise AssertionError("green check failed: %s\n%s" %
                                 (battery, proc.stderr[-2000:]))
    return "; ".join(notes)


def main():
    for probe in PROBES:
        try:
            probe()
        except AssertionError as exc:
            _record(probe.__name__.replace("probe_", "").replace("_", "-"),
                    "ERROR", "assertion: %s" % (exc,))
        except Exception as exc:  # noqa: BLE001 - battery must not die
            _record(probe.__name__.replace("probe_", "").replace("_", "-"),
                    "ERROR", "%s: %s" % (type(exc).__name__, exc))
    held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    gap = sum(1 for r in RESULTS if r["verdict"] == "GAP")
    err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    print("w250 evidence-graph: %d HELD / %d GAP / %d ERROR "
          "of %d probes" % (held, gap, err, len(RESULTS)))
    for r in RESULTS:
        print("  [%s] %s %s" % (r["verdict"], r["probe"], r["detail"]))
    if not SKIP_GREEN and err == 0:
        print("green-check:", green_check())
    digest = hashlib.sha256(
        json.dumps(RESULTS, sort_keys=True).encode()).hexdigest()[:16]
    print("result-digest:", digest)
    return 0 if err == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
