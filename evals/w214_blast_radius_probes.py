#!/usr/bin/env python3
"""Wave-214 lane B break-first battery: BOM blast-radius query discipline.

ADAPT of the GUAC query discipline (wave-212 lane-D prospecting
verdict): GUAC's GraphQL ``usingOnly`` restricts every traversal to an
explicit caller-declared edge set. This module adapts the discipline
only -- reproducible, auditable path/neighbors queries over the
DECISION graph (Decision BOMs, builders, keys, artifacts, scan
verdicts, promotions) -- and deliberately DROPS GUAC's package-graph
backend as a category error for an evidence graph. No GUAC source is
vendored; the discipline is re-described in our own words.

Red-first protocol: this battery is written and run BEFORE the module
exists (pristine RED = import fails / enforcement absent), then re-run
against the implementation (fixed GREEN).

Hypotheses (diagnosing-bugs loop):
  H1 (rank 1): allowlist escape must fail CLOSED -- a traversal whose
     ``using_edges`` declares a non-allowlisted edge kind raises loudly;
     it must never silently skip the unknown kind and return a partial
     answer. Adding a non-allowlisted edge to a graph is refused at
     build time.
  H2 (rank 2): graph cycles must terminate -- reachable() on a directed
     cycle returns each node exactly once, in deterministic order.
  H3 (rank 3): missing-node queries return EMPTY, not errors-as-denials
     -- querying an unknown builder/key/verdict/decision yields [] so
     callers cannot mistake a lookup failure for an exoneration or an
     accusation.
  H4 (rank 4): headline queries are reproducible -- same inputs produce
     byte-identical outputs (deterministic ordering) and every report
     carries the pinned allowlist digest, so the answer is auditable.
  H5 (rank 5): the revocation discipline is honest -- a revoked-builder
     query only answers when the builder node is actually marked
     revoked; a live builder yields [] (no false blast radius).

$0 spend. No network. stdlib only.
"""

import json
import os
import subprocess
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

GREEN_SKIP = os.environ.get("GOV_SKIP_GREEN") == "1"

_RESULTS = []
_PROBE_FNS = {}


def _probe(name):
    def deco(fn):
        def run():
            try:
                detail = fn()
            except ImportError as e:
                _RESULTS.append((name, "ERROR", "missing module: %s" % e))
                return
            except AssertionError as e:
                _RESULTS.append((name, "ERROR", "assertion: %s"
                                 % str(e)[:300]))
                return
            except Exception as e:  # noqa: BLE001 - hostile-input battery
                _RESULTS.append((name, "ERROR", "%s: %s"
                                 % (type(e).__name__, str(e)[:300])))
                return
            verdict, detail = detail
            assert verdict in ("HELD", "BREAK", "RESIDUAL"), verdict
            _RESULTS.append((name, verdict, detail))
        _PROBE_FNS[name] = run
        return run
    return deco


# ------------------------------------------------------------------ helpers

def _bq():
    from gov import bom_queries as bq
    return bq


def _fixture_graph(bq):
    """A synthetic decision graph with known blast radii.

    Nodes: 2 decisions, 1 revoked builder, 1 live builder, 1 key,
    2 artifacts, 1 scan verdict, 2 promotions.
    """
    g = bq.DecisionGraph()
    g.add_node("decision", "dec:001", {"label": "deploy approval"})
    g.add_node("decision", "dec:002", {"label": "config change"})
    g.add_node("builder", "builder:revoked-x", {"revoked": True})
    g.add_node("builder", "builder:live-y", {"revoked": False})
    g.add_node("key", "key:k1", {})
    g.add_node("artifact", "art:a1", {})
    g.add_node("artifact", "art:a2", {})
    g.add_node("scan_verdict", "verdict:v1", {})
    g.add_node("promotion", "promo:p1", {})
    g.add_node("promotion", "promo:p2", {})
    g.add_edge("dec:001", "builder:revoked-x", "decision/used-builder")
    g.add_edge("dec:002", "builder:live-y", "decision/used-builder")
    g.add_edge("dec:001", "key:k1", "decision/attested-by")
    g.add_edge("dec:001", "art:a1", "decision/emitted")
    g.add_edge("art:a1", "key:k1", "artifact/attested-by")
    g.add_edge("dec:002", "art:a2", "decision/emitted")
    g.add_edge("dec:001", "verdict:v1", "decision/consumed-verdict")
    g.add_edge("promo:p1", "dec:001", "promotion/promoted-decision")
    g.add_edge("promo:p2", "dec:002", "promotion/promoted-decision")
    g.add_edge("promo:p1", "verdict:v1", "promotion/admitted-verdict")
    return g


# ------------------------------------------------------------------ probes

@_probe("allowlist_escape_traversal")
def _p_escape_traversal():
    """H1: a traversal declaring a non-allowlisted edge kind must fail
    CLOSED (raise), never silently skip the unknown kind."""
    bq = _bq()
    g = _fixture_graph(bq)
    try:
        bq.reachable(g, "dec:001",
                     using_edges=("decision/emitted", "smuggle/edge"))
    except bq.QueryError as e:
        return "HELD", "escape refused: %s" % str(e)[:160]
    return "BREAK", "non-allowlisted edge kind silently accepted"


@_probe("allowlist_escape_add_edge")
def _p_escape_add_edge():
    """H1: add_edge with a non-allowlisted kind is refused at build
    time (GraphError), so no graph can ever carry a smuggled edge."""
    bq = _bq()
    g = _fixture_graph(bq)
    try:
        g.add_edge("dec:001", "art:a2", "smuggle/edge")
    except bq.GraphError as e:
        return "HELD", "build-time refusal: %s" % str(e)[:160]
    return "BREAK", "non-allowlisted edge admitted to the graph"


@_probe("cycle_terminates")
def _p_cycle():
    """H2: directed cycles terminate; each node reported exactly once."""
    bq = _bq()
    g = bq.DecisionGraph()
    g.add_node("decision", "d1", {})
    g.add_node("artifact", "a1", {})
    g.add_node("decision", "d2", {})
    g.add_edge("d1", "a1", "decision/emitted")
    g.add_edge("a1", "d2", "artifact/derived-from")
    g.add_edge("d2", "a1", "decision/emitted")  # closes the cycle
    got = bq.reachable(g, "d1",
                       using_edges=("decision/emitted",
                                    "artifact/derived-from"))
    # The start node itself is excluded from its own reachable set
    # (documented seam): d1 -> a1 -> d2, and d2 -> a1 closes the cycle
    # without revisiting anyone.
    if got == ["a1", "d2"]:
        return "HELD", "cycle terminated, one visit per node, sorted"
    return "BREAK", "cycle mishandled: %r" % (got,)


@_probe("missing_node_empty")
def _p_missing():
    """H3: unknown builder/key/verdict/decision -> empty, not an
    exception and not an error-shaped denial."""
    bq = _bq()
    g = _fixture_graph(bq)
    outs = [
        bq.decisions_using_builder(g, "builder:ghost"),
        bq.artifacts_emitted_under_key(g, "key:ghost"),
        bq.promotions_depending_on_verdict(g, "verdict:ghost"),
        bq.reachable(g, "decision:ghost",
                     using_edges=("decision/emitted",)),
    ]
    if outs == [[], [], [], []]:
        return "HELD", "all four seams returned [] on unknown ids"
    return "BREAK", "non-empty or raised on unknown ids: %r" % (outs,)


@_probe("decisions_using_revoked_builder")
def _p_revoked_builder():
    """H4/H5: revoked builder X -> exactly the decisions that used X;
    a LIVE builder under the revoked query returns [] (no false blast
    radius); require_revoked=False lists the live builder's decisions."""
    bq = _bq()
    g = _fixture_graph(bq)
    got_revoked = bq.decisions_using_builder(g, "builder:revoked-x")
    got_live = bq.decisions_using_builder(g, "builder:live-y")
    got_live_unfiltered = bq.decisions_using_builder(
        g, "builder:live-y", require_revoked=False)
    if (got_revoked == ["dec:001"] and got_live == []
            and got_live_unfiltered == ["dec:002"]):
        return ("HELD",
                "revoked blast exact; live builder yields [] under "
                "require_revoked=True")
    return ("BREAK",
            "wrong sets: %r %r %r"
            % (got_revoked, got_live, got_live_unfiltered))


@_probe("artifacts_emitted_under_key")
def _p_under_key():
    """H4: artifacts emitted under key K -- both via the decision's
    attestation and via direct artifact attestation."""
    bq = _bq()
    g = _fixture_graph(bq)
    got = bq.artifacts_emitted_under_key(g, "key:k1")
    if got == ["art:a1"]:
        return "HELD", "exact artifact set under key:k1"
    return "BREAK", "wrong artifact set: %r" % (got,)


@_probe("promotions_depending_on_verdict")
def _p_depends_verdict():
    """H4: promotions depending on verdict V -- direct admission edge
    AND the two-hop path promotion -> decision -> consumed-verdict."""
    bq = _bq()
    g = _fixture_graph(bq)
    got = bq.promotions_depending_on_verdict(g, "verdict:v1")
    if got == ["promo:p1"]:
        return "HELD", "exact promotion set depending on verdict:v1"
    return "BREAK", "wrong promotion set: %r" % (got,)


@_probe("determinism_and_allowlist_pin")
def _p_determinism():
    """H4: same inputs -> byte-identical reports; the allowlist digest
    is pinned in every report and stable across runs."""
    bq = _bq()
    g = _fixture_graph(bq)
    r1 = bq.query_report(g, "decisions_using_builder",
                         {"builder_id": "builder:revoked-x"})
    r2 = bq.query_report(g, "decisions_using_builder",
                         {"builder_id": "builder:revoked-x"})
    if r1 != r2:
        return "BREAK", "report not reproducible across runs"
    d1 = bq.allowlist_digest()
    d2 = bq.allowlist_digest()
    if d1 != d2 or len(d1) != 64:
        return "BREAK", "allowlist digest unstable or malformed"
    if r1.get("allowlist_digest") != d1:
        return "BREAK", "report does not carry the pinned allowlist"
    qd1 = bq.report_digest(r1)
    qd2 = bq.report_digest(r2)
    if qd1 != qd2:
        return "BREAK", "report digest unstable"
    return "HELD", ("reports byte-identical; allowlist=%s...; "
                    "report_digest=%s..." % (d1[:16], qd1[:16]))


@_probe("using_only_defaults_pinned")
def _p_defaults():
    """The allowlist is frozen (no mutation API) and every query's
    default using-edges are a declared subset of it."""
    bq = _bq()
    g = _fixture_graph(bq)
    al = bq.ALLOWLIST
    if not isinstance(al, frozenset):
        return "BREAK", "ALLOWLIST is not a frozen set"
    defaults = bq.DEFAULT_USING_EDGES
    for name, using in defaults.items():
        for e in using:
            if e not in al:
                return ("BREAK",
                        "query %s default edge %r not in allowlist"
                        % (name, e))
    if "smuggle/edge" in al:
        return "BREAK", "allowlist admits a bogus kind"
    return "HELD", ("defaults pinned: %d kinds in allowlist; all query "
                    "defaults are subsets" % len(al))


@_probe("allowlist_signature")
def _p_signature():
    """The allowlist is SIGNED, not just pinned: a valid Ed25519
    signature verifies; a tampered record (an edge smuggled into the
    signed set) and a wrong-key verifier fail closed."""
    bq = _bq()
    from gov.signing import Ed25519Signer, Ed25519Verifier
    signer = Ed25519Signer(b"\x01" * 32)
    verifier = Ed25519Verifier(signer.public_key)
    signed = bq.sign_allowlist(signer)
    try:
        rec = bq.verify_allowlist_signature(verifier, signed)
    except bq.GraphError as e:
        return "BREAK", "valid signature refused: %s" % str(e)[:160]
    if rec != bq.allowlist_record():
        return "BREAK", "verified record does not match allowlist_record"
    tampered = {"record": dict(signed["record"]),
                "key_id": signed["key_id"],
                "signature": signed["signature"]}
    tampered["record"]["edges"] = (signed["record"]["edges"]
                                   + ["smuggle/x"])
    try:
        bq.verify_allowlist_signature(verifier, tampered)
        return "BREAK", "tampered allowlist record verified"
    except bq.GraphError:
        pass
    other = Ed25519Verifier(Ed25519Signer(b"\x02" * 32).public_key)
    try:
        bq.verify_allowlist_signature(other, signed)
        return "BREAK", "wrong-key signature verified"
    except bq.GraphError:
        pass
    return "HELD", "sign/verify round-trip; tamper and key-swap refused"


@_probe("green_adjacent")
def _p_green():
    """Depth-1 green check: the adjacent decision_bom unit suite must
    stay green (GOV_SKIP_GREEN=1 so the child does not recurse)."""
    if GREEN_SKIP:
        return "HELD", "skipped (GOV_SKIP_GREEN=1)"
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    p = subprocess.run(
        [sys.executable, "-m", "unittest", "tests.test_decision_bom"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=300)
    if p.returncode == 0:
        return "HELD", "adjacent test_decision_bom green"
    return ("ERROR",
            "adjacent suite failed: %s" % (p.stderr[-400:] or p.stdout[-400:]))


# ------------------------------------------------------------------ runner

def _summarize():
    held = sum(1 for _, v, _ in _RESULTS if v == "HELD")
    brk = sum(1 for _, v, _ in _RESULTS if v == "BREAK")
    res = sum(1 for _, v, _ in _RESULTS if v == "RESIDUAL")
    err = sum(1 for _, v, _ in _RESULTS if v == "ERROR")
    return held, brk, res, err


def main():
    order = sorted(_PROBE_FNS)
    for name in order:
        _PROBE_FNS[name]()          # pass 1
    # Determinism: every probe runs twice; a verdict change is ERROR.
    first = list(_RESULTS)
    _RESULTS.clear()
    for name in order:
        _PROBE_FNS[name]()          # pass 2
    for (n1, v1, _), (n2, v2, _) in zip(first, _RESULTS):
        assert n1 == n2, "probe order changed between passes"
        if v1 != v2:
            _RESULTS.append((n1, "ERROR",
                             "nondeterministic verdict %s -> %s" % (v1, v2)))
    held, brk, res, err = _summarize()
    print("=== wave-214 lane B blast-radius battery ===")
    for name, verdict, detail in _RESULTS:
        print("%-36s %-8s %s" % (name, verdict, detail))
    print("--- %d HELD / %d BREAK / %d RESIDUAL / %d ERROR ---"
          % (held, brk, res, err))
    return 0 if (brk == 0 and err == 0) else 1


if __name__ == "__main__":
    sys.exit(main())
