"""Wave-282 lane 7 red-first battery: BloodHound attack-path ADAPT.

Base: wave-281 push a858be2. The gap under test is the absence of a
continuous attack-path audit primitive: the grant graph (delegation
tokens, ephemeral grants, approvals, provenance checkpoints) has no
typed-edge analysis, no shortest-path-to-high-value queries, and no
automatic findings enumeration. BloodHound's primitive (typed edges +
composition, shortest paths to marked high-value targets, automatic
findings) is ADAPTED here as gov/attack_paths.py -- mechanism only,
Apache-2.0 CE contract shapes, stdlib graph (no Neo4j), no code vendored.

Red-first: on the pristine base (module absent) every capability probe
BREAKs. After the build, all HELD in staging and
env -u GOV_DEPLOYMENT_MODE.

$0 spend, synthetic/local, deterministic (no wall-clock assertions).
Stdlib only, no in-repo git subprocesses.

Run:
  mkdir -p /var/tmp/g282-bloodhound && TMPDIR=/var/tmp/g282-bloodhound \
    ~/workspace/.gov-venv/bin/python evals/w282_bloodhound_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g282-bloodhound2 \
    ~/workspace/.gov-venv/bin/python evals/w282_bloodhound_probes.py
"""

import os
import re
import secrets
import sys
import tempfile

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w282-bloodhound")
os.environ.setdefault("TMPDIR", "/var/tmp/g282-bloodhound")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TAXONOMY_PIN = 2131  # Wave-342 lane 6: pin 2131 -> 2127 (-4 family-fallback base-class codes).


_RESULTS = []

PLUGIN_META = ("authz-bypass", "direct", "held-vs-expected")
PROBE_METADATA = {}


def _record(probe_id, verdict, note):
    _RESULTS.append({"probe_id": probe_id, "verdict": verdict, "note": note})
    PROBE_METADATA.setdefault(probe_id, PLUGIN_META)


def _needs_modules(probe_id):
    try:
        from gov import attack_paths as ap
        return ap
    except ImportError:
        _record(probe_id, "BREAK", "gov.attack_paths absent on base")
        return None


def _literals():
    with open(os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "gov", "decision_codes.py"),
            encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


def p_taxonomy_pin():
    lits = _literals()
    if len(lits) != TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted" % (TAXONOMY_PIN, TAXONOMY_PIN))


def _demo_graph(ap):
    """Agent a1 delegates to a2; a2 granted exfil tool t1 without a
    provenance checkpoint; a1 also reaches t1 via checkpointed grant."""
    g = ap.GrantGraph()
    g.add_node("a1", "agent")
    g.add_node("a2", "agent")
    g.add_node("t1", "tool", labels={"exfil-capable"})
    g.add_node("t2", "tool")
    g.add_edge("a2", "t1", "granted_to")  # NO checkpoint
    g.add_edge("a1", "a2", "delegated_by")
    g.add_edge("a1", "t2", "granted_to", provenance_checkpoint=True)
    g.mark_high_value("t1")
    return g


def p_graph_construction():
    ap = _needs_modules("p_graph_construction")
    if ap is None:
        return
    g = ap.GrantGraph()
    g.add_node("a", "agent", labels={"low-trust"})
    g.add_node("t", "tool", labels={"exfil-capable"})
    g.add_edge("a", "t", "granted_to", provenance_checkpoint=True)
    nodes = g.nodes()
    if set(nodes) != {"a", "t"}:
        return _record("p_graph_construction", "BREAK",
                       "nodes mismatch: %r" % sorted(nodes))
    if g.edge("a", "t", "granted_to")["provenance_checkpoint"] is not True:
        return _record("p_graph_construction", "BREAK",
                       "edge attribute not preserved")
    _record("p_graph_construction", "HELD", "nodes/edges/attributes register")


def p_closed_vocabularies():
    ap = _needs_modules("p_closed_vocabularies")
    if ap is None:
        return
    g = ap.GrantGraph()
    g.add_node("a", "agent")
    g.add_node("t", "tool")
    try:
        g.add_edge("a", "t", "owns")  # not in closed vocabulary
    except ap.AttackPathError as e:
        if e.code != "attackpath-unknown-edge-type":
            return _record("p_closed_vocabularies", "BREAK",
                           "wrong code: %r" % e.code)
    else:
        return _record("p_closed_vocabularies", "BREAK",
                       "unknown edge type accepted")
    try:
        g.add_edge("ghost", "t", "granted_to")
    except ap.AttackPathError as e:
        if e.code != "attackpath-unknown-node":
            return _record("p_closed_vocabularies", "BREAK",
                           "wrong code: %r" % e.code)
    else:
        return _record("p_closed_vocabularies", "BREAK",
                       "unknown node accepted")
    try:
        g.add_node("a", "agent")
    except ap.AttackPathError as e:
        if e.code != "attackpath-duplicate-node":
            return _record("p_closed_vocabularies", "BREAK",
                           "wrong code: %r" % e.code)
    else:
        return _record("p_closed_vocabularies", "BREAK",
                       "duplicate node accepted")
    _record("p_closed_vocabularies", "HELD",
            "unknown edge/node refused, duplicate refused")


def p_edge_composition():
    ap = _needs_modules("p_edge_composition")
    if ap is None:
        return
    g = _demo_graph(ap)
    # a1 -> delegated_by -> a2 -> granted_to -> t1 : can_call by composition
    if not ap.can_call(g, "a1", "t1"):
        return _record("p_edge_composition", "BREAK",
                       "delegated can_call not derived")
    # direct grant also works
    if not ap.can_call(g, "a2", "t1"):
        return _record("p_edge_composition", "BREAK",
                       "direct can_call not derived")
    # negative control: no edge anywhere
    if ap.can_call(g, "a1", "nope"):
        return _record("p_edge_composition", "BREAK",
                       "phantom can_call true")
    _record("p_edge_composition", "HELD",
            "granted_to + delegated_by composition derives can_call")


def p_shortest_paths():
    ap = _needs_modules("p_shortest_paths")
    if ap is None:
        return
    g = _demo_graph(ap)
    paths = ap.shortest_paths(g, "a1", "t1")
    if len(paths) != 1:
        return _record("p_shortest_paths", "BREAK",
                       "expected 1 shortest path, got %d" % len(paths))
    hops = [(h[0], h[1], h[2]) for h in paths[0]]
    if hops != [("a1", "delegated_by", "a2"), ("a2", "granted_to", "t1")]:
        return _record("p_shortest_paths", "BREAK",
                       "wrong hops: %r" % (hops,))
    # add a longer alternate route; shortest must stay length 2
    g.add_node("a3", "agent")
    g.add_edge("a1", "a3", "delegated_by")
    g.add_edge("a3", "a2", "delegated_by")
    paths2 = ap.shortest_paths(g, "a1", "t1")
    if any(len(p) != 2 for p in paths2):
        return _record("p_shortest_paths", "BREAK",
                       "non-minimal paths returned")
    _record("p_shortest_paths", "HELD", "BFS minimal, cycle of detours ignored")


def p_cycles_safe():
    ap = _needs_modules("p_cycles_safe")
    if ap is None:
        return
    g = ap.GrantGraph()
    g.add_node("a1", "agent")
    g.add_node("a2", "agent")
    g.add_node("t", "tool")
    g.add_edge("a1", "a2", "delegated_by")
    g.add_edge("a2", "a1", "delegated_by")  # cycle
    g.add_edge("a2", "t", "granted_to")
    paths = ap.shortest_paths(g, "a1", "t")
    if len(paths) != 1 or len(paths[0]) != 2:
        return _record("p_cycles_safe", "BREAK",
                       "cycle broke BFS: %r" % (paths,))
    if ap.can_call(g, "a1", "t") is not True:
        return _record("p_cycles_safe", "BREAK",
                       "can_call false across cycle")
    findings = ap.enumerate_findings(g)
    kinds = [f["finding_kind"] for f in findings]
    if "delegation-cycle" not in kinds:
        return _record("p_cycles_safe", "BREAK",
                       "delegation cycle not enumerated: %r" % (kinds,))
    _record("p_cycles_safe", "HELD",
            "BFS terminates on cycles; cycle enumerated as finding")


def p_waypoint_enforcement():
    ap = _needs_modules("p_waypoint_enforcement")
    if ap is None:
        return
    g = _demo_graph(ap)  # a2 -> t1 has NO checkpoint; t1 is high-value
    findings = ap.enumerate_findings(g)
    wp = [f for f in findings
          if f["finding_kind"] == "unprovenanced-path-to-high-value"]
    if not wp:
        return _record("p_waypoint_enforcement", "BREAK",
                       "unprovenanced path to high-value tool not flagged")
    f = wp[0]
    if f["target"] != "t1":
        return _record("p_waypoint_enforcement", "BREAK",
                       "wrong target: %r" % f["target"])
    # checkpointed path a1 -> t2 must NOT produce a finding
    g.mark_high_value("t2")
    findings2 = ap.enumerate_findings(g)
    wp2 = [f for f in findings2
           if f["finding_kind"] == "unprovenanced-path-to-high-value"
           and f["target"] == "t2"]
    if wp2:
        return _record("p_waypoint_enforcement", "BREAK",
                       "checkpointed path falsely flagged")
    _record("p_waypoint_enforcement", "HELD",
            "unprovenanced path flagged; checkpointed path clean")


def p_checked_edge_gates():
    ap = _needs_modules("p_checked_edge_gates")
    if ap is None:
        return
    # A deployed provenance checkpoint (checkpoint -> tool `checked`
    # edge) gates the tool: grants to it count as waypoint-clean even
    # without the per-edge attribute.
    g = ap.GrantGraph()
    g.add_node("a", "agent")
    g.add_node("t", "tool", labels={"exfil-capable"})
    g.add_node("cp", "checkpoint")
    g.add_edge("a", "t", "granted_to")  # no checkpoint attribute
    g.add_edge("cp", "t", "checked")    # checkpoint deployed on t
    g.mark_high_value("t")
    wp = [f for f in ap.enumerate_findings(g)
          if f["finding_kind"] == "unprovenanced-path-to-high-value"
          and f["target"] == "t"]
    if wp:
        return _record("p_checked_edge_gates", "BREAK",
                       "checked-gated tool falsely flagged")
    # negative control: same graph minus the checked edge must flag
    g2 = ap.GrantGraph()
    g2.add_node("a", "agent")
    g2.add_node("t", "tool", labels={"exfil-capable"})
    g2.add_edge("a", "t", "granted_to")
    g2.mark_high_value("t")
    wp2 = [f for f in ap.enumerate_findings(g2)
           if f["finding_kind"] == "unprovenanced-path-to-high-value"
           and f["target"] == "t"]
    if not wp2:
        return _record("p_checked_edge_gates", "BREAK",
                       "unchecked grant not flagged")
    _record("p_checked_edge_gates", "HELD",
            "checked edge gates tool; unchecked grant flagged")


def p_unapproved_grant():
    ap = _needs_modules("p_unapproved_grant")
    if ap is None:
        return
    g = ap.GrantGraph()
    g.add_node("a", "agent")
    g.add_node("t", "tool", labels={"credential-bearing"})
    g.add_node("appr", "approval")
    g.add_edge("a", "t", "granted_to", provenance_checkpoint=True)
    g.mark_high_value("t")
    findings = ap.enumerate_findings(g)
    kinds = [f["finding_kind"] for f in findings]
    if "unapproved-high-value-grant" not in kinds:
        return _record("p_unapproved_grant", "BREAK",
                       "unapproved grant not enumerated: %r" % (kinds,))
    # attach an approval record -> finding gone
    g.add_edge("appr", "t", "approved")
    findings2 = ap.enumerate_findings(g)
    kinds2 = [f["finding_kind"] for f in findings2]
    if "unapproved-high-value-grant" in kinds2:
        return _record("p_unapproved_grant", "BREAK",
                       "approved grant still flagged")
    _record("p_unapproved_grant", "HELD",
            "unapproved high-value grant flagged; approved clean")


def p_findings_machine_readable():
    ap = _needs_modules("p_findings_machine_readable")
    if ap is None:
        return
    g = _demo_graph(ap)
    findings = ap.enumerate_findings(g)
    if not findings:
        return _record("p_findings_machine_readable", "BREAK",
                       "no findings enumerated")
    required = {"finding_kind", "source", "target", "path",
                "missing_waypoints", "finding_digest"}
    for f in findings:
        if not required.issubset(f):
            return _record("p_findings_machine_readable", "BREAK",
                           "finding missing keys: %r"
                           % (required - set(f)))
        if not isinstance(f["finding_digest"], str) or len(f["finding_digest"]) != 64:
            return _record("p_findings_machine_readable", "BREAK",
                           "finding_digest not sha256 hex")
    # determinism: enumerate twice, digests identical
    again = ap.enumerate_findings(g)
    d1 = sorted(f["finding_digest"] for f in findings)
    d2 = sorted(f["finding_digest"] for f in again)
    if d1 != d2:
        return _record("p_findings_machine_readable", "BREAK",
                       "findings not deterministic")
    _record("p_findings_machine_readable", "HELD",
            "%d findings, machine-readable, deterministic" % len(findings))


def p_writer_chains():
    ap = _needs_modules("p_writer_chains")
    if ap is None:
        return
    from gov.log import ActionLog
    from tests.keyfixture import provision_test_key
    provision_test_key()
    tmp = tempfile.mkdtemp(prefix="g282-bloodhound-")
    log = ActionLog(os.path.join(tmp, "audit.jsonl"))
    g = _demo_graph(ap)
    findings = ap.enumerate_findings(g)
    w = ap.AttackPathWriter(log)
    entries = w.write_findings(findings)
    if len(entries) != len(findings):
        return _record("p_writer_chains", "BREAK",
                       "entry count mismatch")
    records = ap.attack_path_records(log)
    if len(records) != len(findings):
        return _record("p_writer_chains", "BREAK",
                       "records not readable back")
    if ap.verify_attack_path_records(records) is not True:
        return _record("p_writer_chains", "BREAK",
                       "chain verification failed")
    # per-writer chain continuity
    digests = [r["record_digest"] for r in records]
    prevs = [r["prev_attack_path_digest"] for r in records]
    if prevs[0] != ap._GENESIS or prevs[1:] != digests[:-1]:
        return _record("p_writer_chains", "BREAK",
                       "writer chain not continuous")
    _record("p_writer_chains", "HELD",
            "%d findings chained into HMAC log, verify true" % len(findings))


def p_writer_verify_tamper():
    ap = _needs_modules("p_writer_verify_tamper")
    if ap is None:
        return
    from gov.log import ActionLog
    from tests.keyfixture import provision_test_key
    provision_test_key()
    tmp = tempfile.mkdtemp(prefix="g282-bloodhound-")
    log = ActionLog(os.path.join(tmp, "audit.jsonl"))
    g = _demo_graph(ap)
    w = ap.AttackPathWriter(log)
    w.write_findings(ap.enumerate_findings(g))
    records = ap.attack_path_records(log)
    records[0]["finding_kind"] = "forged-kind"
    if ap.verify_attack_path_records(records) is not False:
        return _record("p_writer_verify_tamper", "BREAK",
                       "tampered record verified true")
    _record("p_writer_verify_tamper", "HELD", "tamper detected, verify false")


def _green_check(mod_name):
    if os.environ.get("GOV_SKIP_GREEN") == "1":
        _record("green-" + mod_name, "HELD", "skipped (depth-1)")
        return
    import subprocess
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    r = subprocess.run(
        [sys.executable, "evals/%s_probes.py" % mod_name],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True, text=True, env=env, timeout=600)
    out = (r.stdout or "") + (r.stderr or "")
    # The adjacent red-team battery honestly reports BREAKs for open
    # findings (F310 is OPEN on this base); green = it ran clean with
    # no ERRORs.
    bad = ("[ERROR]" in out) or (r.returncode != 0)
    _record("green-" + mod_name, "HELD" if not bad else "BREAK",
            "rc=%d" % r.returncode)


def main():
    os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    p_taxonomy_pin()
    p_graph_construction()
    p_closed_vocabularies()
    p_edge_composition()
    p_shortest_paths()
    p_cycles_safe()
    p_waypoint_enforcement()
    p_checked_edge_gates()
    p_unapproved_grant()
    p_findings_machine_readable()
    p_writer_chains()
    p_writer_verify_tamper()
    _green_check("w281_redteam")

    n_break = sum(1 for r in _RESULTS if r["verdict"] == "BREAK")
    n_held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    n_err = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("[%s] %s: %s" % (r["verdict"], r["probe_id"], r["note"]))
    print("== %d BREAK / %d HELD / %d ERROR ==" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
