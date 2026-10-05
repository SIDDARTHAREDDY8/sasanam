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

TAXONOMY_PIN = 2127 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable). Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


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
    return "HELD" if got["owner"] == "team-a" and\
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
        return "HELD" if exc.code ==\
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
