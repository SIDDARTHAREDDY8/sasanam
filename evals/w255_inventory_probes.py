"""Break-first battery for gov/inventory_catalog.py (wave-255 lane 4).

Backstage (Apache-2.0) pattern adaptation: a declarative agent/tool/skill
inventory catalog whose unresolvable relationships refuse fail-closed at
load time, with posture scorecards attached at the public seam.

Red-first discipline: every probe is GAP on a pristine base (module
absent), HELD when the implementation holds, BREAK when a break attempt
succeeds. A genuine BREAK against the final implementation would file a
finding; this battery must be all HELD on the shipped module.
"""

import copy
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TAXONOMY_PIN = 1106  # Wave-258 merge: pin -> 1106.

try:
    from gov import inventory_catalog as ic
    from gov import decision_codes
    HAVE_MODULE = True
except ImportError:
    HAVE_MODULE = False


def _good_entry(name, kind="agent", rels=()):
    e = {"kind": kind, "name": name, "owner": "team-a"}
    if rels:
        e["relationships"] = list(rels)
    return e


def _good_catalog():
    return ic.load_catalog([
        _good_entry("agent-1", rels=[
            {"to": "tool-x", "type": "uses"},
            {"to": "skill-y", "type": "grant"},
        ]),
        _good_entry("tool-x", kind="tool"),
        _good_entry("skill-y", kind="skill"),
    ])


def _good_cards():
    return [
        {"track": "policy", "check": "c1", "score": 0.8,
         "reason": "r", "remediation": "m"},
        {"track": "identity", "check": "c2", "score": 0.5,
         "reason": "r", "remediation": "m"},
    ]


def _refused_with(fn, code):
    try:
        fn()
    except ic.CatalogRefused as exc:
        return exc.code == code
    except Exception:
        return False
    return False


PROBES = []


def probe(fn):
    PROBES.append(fn)
    return fn


@probe
def p_dangling_reference():
    """An entry referencing a nonexistent name must refuse fail-closed."""
    def run():
        ic.load_catalog([_good_entry("agent-1", rels=[
            {"to": "ghost-tool", "type": "uses"}])])
    ok = _refused_with(run, "inventory-catalog-dangling-reference")
    return "HELD" if ok else "BREAK"


@probe
def p_duplicate_name():
    """Two entries with the same name must refuse."""
    def run():
        ic.load_catalog([_good_entry("agent-1"),
                         _good_entry("agent-1", kind="tool")])
    ok = _refused_with(run, "inventory-catalog-duplicate-entry")
    return "HELD" if ok else "BREAK"


@probe
def p_malformed_missing_name():
    """An entry without a name must refuse."""
    def run():
        ic.load_catalog([{"kind": "agent", "owner": "team-a"}])
    ok = _refused_with(run, "inventory-catalog-entry-malformed")
    return "HELD" if ok else "BREAK"


@probe
def p_malformed_bad_kind():
    """An entry with an unknown kind must refuse."""
    def run():
        ic.load_catalog([{"kind": "daemon", "name": "d1",
                          "owner": "team-a"}])
    ok = _refused_with(run, "inventory-catalog-entry-malformed")
    return "HELD" if ok else "BREAK"


@probe
def p_malformed_relationship_type():
    """An unknown relationship type must refuse."""
    def run():
        ic.load_catalog([
            _good_entry("agent-1", rels=[
                {"to": "tool-x", "type": "pwns"}]),
            _good_entry("tool-x", kind="tool"),
        ])
    ok = _refused_with(run, "inventory-catalog-entry-malformed")
    return "HELD" if ok else "BREAK"


@probe
def p_non_list_relationships():
    """A non-list relationships field must refuse, not crash."""
    def run():
        e = _good_entry("agent-1")
        e["relationships"] = "tool-x"
        ic.load_catalog([e])
    ok = _refused_with(run, "inventory-catalog-entry-malformed")
    return "HELD" if ok else "BREAK"


@probe
def p_scorecard_non_dict_cards():
    """Attaching non-dict cards must refuse (F215 class), not crash."""
    cat = _good_catalog()

    def run():
        ic.attach_scorecard(cat, "agent-1", ["not-a-dict"])
    ok = _refused_with(run, "inventory-catalog-card-malformed")
    return "HELD" if ok else "BREAK"


@probe
def p_attach_unknown_entry():
    """Attaching a scorecard to an unknown entry must refuse."""
    cat = _good_catalog()

    def run():
        ic.attach_scorecard(cat, "ghost", _good_cards())
    ok = _refused_with(run, "inventory-catalog-unknown-entry")
    return "HELD" if ok else "BREAK"


@probe
def p_report_unknown_entry():
    """Reporting an unknown entry must refuse."""
    cat = _good_catalog()

    def run():
        ic.report(cat, "ghost")
    ok = _refused_with(run, "inventory-catalog-unknown-entry")
    return "HELD" if ok else "BREAK"


@probe
def p_grant_edge_seam_unavailable():
    """A grant relationship with no grants provider must refuse
    fail-closed (the keto seam is deployment-supplied)."""
    cat = _good_catalog()

    def run():
        ic.grant_edges(cat, grants_provider=None)
    ok = _refused_with(run, "inventory-catalog-seam-unavailable")
    return "HELD" if ok else "BREAK"


@probe
def p_grant_edge_unresolved():
    """A grant the provider does not confirm must refuse, never pass."""
    cat = _good_catalog()

    def provider(agent, tool):
        return False

    def run():
        ic.grant_edges(cat, grants_provider=provider)
    ok = _refused_with(run, "inventory-catalog-grant-unresolved")
    return "HELD" if ok else "BREAK"


@probe
def p_grant_edge_resolved():
    """A provider-confirmed grant must resolve (positive control)."""
    cat = _good_catalog()

    def provider(agent, tool):
        return agent == "agent-1" and tool == "skill-y"

    try:
        edges = ic.grant_edges(cat, grants_provider=provider)
    except Exception:
        return "BREAK"
    return "HELD" if edges == [("agent-1", "skill-y")] else "BREAK"


@probe
def p_cycle_loads():
    """A relationship cycle is resolvable and must load without
    hanging or crashing."""
    try:
        cat = ic.load_catalog([
            _good_entry("agent-1", rels=[
                {"to": "tool-x", "type": "uses"}]),
            _good_entry("tool-x", kind="tool", rels=[
                {"to": "agent-1", "type": "owns"}]),
        ])
    except Exception:
        return "BREAK"
    return "HELD" if sorted(cat.names()) == ["agent-1", "tool-x"] else "BREAK"


@probe
def p_mutation_isolation():
    """Caller mutation after load must not corrupt catalog state."""
    entry = _good_entry("agent-1")
    cat = ic.load_catalog([entry])
    entry["owner"] = "attacker"
    entry["relationships"] = [{"to": "ghost", "type": "uses"}]
    try:
        got = ic.entry_of(cat, "agent-1")
    except Exception:
        return "BREAK"
    return "HELD" if got["owner"] == "team-a" and \
        got["relationships"] == [] else "BREAK"


@probe
def p_report_without_scorecard():
    """An entry report with no attached scorecard must work, with an
    empty scorecard section -- not crash."""
    cat = _good_catalog()
    try:
        rep = ic.report(cat, "agent-1")
    except Exception:
        return "BREAK"
    ok = (rep["entry"]["name"] == "agent-1"
          and rep["scorecard"] is None)
    return "HELD" if ok else "BREAK"


@probe
def p_report_with_scorecard():
    """An attached scorecard must surface per-track levels from the
    posture_cards public seam."""
    cat = ic.attach_scorecard(_good_catalog(), "agent-1", _good_cards())
    try:
        rep = ic.report(cat, "agent-1")
    except Exception:
        return "BREAK"
    sc = rep["scorecard"]
    ok = (isinstance(sc, dict) and "policy" in sc and "identity" in sc)
    return "HELD" if ok else "BREAK"


@probe
def p_taxonomy_pin():
    """Taxonomy is exactly the lane pin: base 1029 + 7 additive."""
    try:
        n = len(decision_codes.TAXONOMY)  # Wave-258 merge: pin -> 1080.
        uniq = len(set(decision_codes.TAXONOMY.keys()))
        for code in ("inventory-catalog-card-malformed",
                     "inventory-catalog-dangling-reference",
                     "inventory-catalog-duplicate-entry",
                     "inventory-catalog-entry-malformed",
                     "inventory-catalog-grant-unresolved",
                     "inventory-catalog-seam-unavailable",
                     "inventory-catalog-unknown-entry"):
            decision_codes.code_for(code)
    except Exception:
        return "BREAK"
    return "HELD" if (n, uniq) == (TAXONOMY_PIN, TAXONOMY_PIN) else "BREAK"


@probe
def p_registered_predicate():
    """The discovery-stream predicate answers true for declared names
    and false for anything else."""
    cat = _good_catalog()
    ok = (ic.is_registered_name(cat, "agent-1") is True
          and ic.is_registered_name(cat, "ghost") is False)
    return "HELD" if ok else "BREAK"


@probe
def p_registered_predicate_refuses():
    """The predicate refuses on a non-Catalog, never guesses."""
    try:
        ic.is_registered_name({"agent-1": {}}, "agent-1")
    except ic.CatalogRefused as exc:
        return "HELD" if exc.code == \
            "inventory-catalog-entry-malformed" else "BREAK"
    except Exception:
        return "BREAK"
    return "BREAK"


def green_check():
    """Depth-1 adjacent checks. Honors GOV_SKIP_GREEN."""
    if os.environ.get("GOV_SKIP_GREEN"):
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return True
    import subprocess
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    adj = [
        [sys.executable, "-m", "unittest", "tests.test_posture_cards",
         "-v"],
        [sys.executable, "-m", "unittest", "tests.test_decision_codes",
         "-v"],
    ]
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    td = "/var/tmp/g255-inv-green"
    os.makedirs(td, exist_ok=True)
    env["TMPDIR"] = td
    for cmd in adj:
        r = subprocess.run(cmd, cwd=repo, env=env, capture_output=True,
                           text=True, timeout=600)
        if r.returncode != 0:
            print("GREEN CHECK FAILED:", " ".join(cmd))
            print(r.stdout[-2000:])
            print(r.stderr[-2000:])
            return False
    print("GREEN CHECK: posture_cards + decision_codes green")
    return True


def main():
    results = []
    if not HAVE_MODULE:
        for p in PROBES:
            results.append((p.__name__, "GAP"))
    else:
        for p in PROBES:
            try:
                results.append((p.__name__, p()))
            except Exception as exc:  # never mask a crash
                results.append((p.__name__, "BREAK(%r)" % (exc,)))
    held = sum(1 for _, v in results if v == "HELD")
    brk = sum(1 for _, v in results if v.startswith("BREAK"))
    gap = sum(1 for _, v in results if v == "GAP")
    for name, verdict in results:
        print("%-38s %s" % (name, verdict))
    print("HELD %d / BREAK %d / GAP %d of %d" % (held, brk, gap,
                                                 len(results)))
    ok = green_check()
    return held, brk, gap, ok


if __name__ == "__main__":
    held, brk, gap, ok = main()
    sys.exit(0 if (gap or (held, brk, gap) == (len(PROBES), 0, 0)) and ok
             else 1)
