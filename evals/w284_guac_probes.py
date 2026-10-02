"""Break-first red battery: GUAC-pattern evidence graph (wave-284 lane 5;
guacsec/guac STEAL, Apache-2.0, pattern only).

The gap under test: the tree has an aggregation evidence graph
(``gov/evidence_graph.py``, wave-250) but no typed evidence/actor/
software/artifact triad ontology, no GUAC edge vocabulary (``CertifyBad``
blast-radius, ``IsOccurrence`` deployment facts), no DSSE-first
ingestion (bundles as envelopes first, graph nodes second), and no
closed ``*Spec`` filter structs. Collector claims are also
uncorroborated -- this module holds them ``pending`` until >=2 distinct
actor principals assert the same claim.

On the pristine wave-283 base every probe reports BREAK (the module
does not exist). After the build, every probe must report HELD under
both staging and a clean environment.

Synthetic/local only. Deterministic: fixed seeds, no wall clock in
asserted values, sorted assertions. Stdlib only, no in-repo git
subprocesses. Module-level staging default; verified under
``env -u GOV_DEPLOYMENT_MODE``.
"""

import hashlib
import json
import os
import re
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# Repo root (this file lives in evals/) so `gov` is importable when the
# battery is run from anywhere.
sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

RESULTS = []


def _record(name, verdict, detail=""):
    RESULTS.append({"probe": name, "verdict": verdict, "detail": detail})
    return verdict


def _module():
    try:
        from gov import guac_graph
        return guac_graph, None
    except ImportError as exc:  # noqa: BLE001 - importability is the gap
        return None, str(exc)


def _keys():
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s1 = Ed25519Signer(b"\x51" * 32)
    s2 = Ed25519Signer(b"\x52" * 32)
    s3 = Ed25519Signer(b"\x53" * 32)
    v1 = Ed25519Verifier(s1.public_key)
    v2 = Ed25519Verifier(s2.public_key)
    v3 = Ed25519Verifier(s3.public_key)
    return (s1, s2, s3), (v1, v2, v3)


# ----------------------------------------------------------------------
# probes
# ----------------------------------------------------------------------

def p_module_absent():
    gg, reason = _module()
    if gg is None:
        return _record("module-exists", "BREAK", reason)
    return _record("module-exists", "HELD", "gov.guac_graph importable")


def p_schema_pinned():
    gg, _ = _module()
    if gg is None:
        return _record("schema-pinned", "BREAK", "module absent")
    if gg.SCHEMA_VERSION != 1:
        return _record("schema-pinned", "BREAK",
                       "schema version drifted: %r" % (gg.SCHEMA_VERSION,))
    if not gg.GUAC_STATEMENT_PAYLOAD_TYPE.startswith("application/"):
        return _record("schema-pinned", "BREAK", "payload type not bound")
    return _record("schema-pinned", "HELD", "schema v1, payload type bound")


def p_triad_ontology():
    gg, _ = _module()
    if gg is None:
        return _record("triad-ontology", "BREAK", "module absent")
    for t in ("evidence", "actor", "software", "artifact"):
        if t not in gg.NODE_TYPES:
            return _record("triad-ontology", "BREAK", "missing node %r" % t)
    g = gg.GuacGraph()
    a = g.add_node("actor", "a" * 16)
    s = g.add_node("software", "skill-x@1.0")
    e = g.add_node("evidence", "b" * 64)
    try:
        g.add_node("package", "whatever")
        return _record("triad-ontology", "BREAK", "untyped node accepted")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-malformed":
            return _record("triad-ontology", "BREAK",
                           "wrong code: %s" % exc.code)
    return _record("triad-ontology", "HELD",
                   "triad %s closed vocabulary" % sorted(gg.NODE_TYPES))


def p_edge_vocabulary():
    gg, _ = _module()
    if gg is None:
        return _record("edge-vocabulary", "BREAK", "module absent")
    for k in ("CertifyBad", "CertifyGood", "IsOccurrence", "IsDependency",
              "HasSBOM", "HasSLSA", "CertifyVuln", "HashEqual", "PkgEqual",
              "HasSourceAt", "HasMetadata"):
        if k not in gg.EDGE_KINDS:
            return _record("edge-vocabulary", "BREAK", "missing edge %r" % k)
    g = gg.GuacGraph()
    a = g.add_node("actor", "a" * 16)
    s = g.add_node("software", "skill-x@1.0")
    try:
        g.add_edge(a, "IsDependency", s)  # wrong shape: software->software
        return _record("edge-vocabulary", "BREAK",
                       "shape violation accepted")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-malformed":
            return _record("edge-vocabulary", "BREAK",
                           "wrong code: %s" % exc.code)
    try:
        g.add_edge(a, "NopeBad", s)
        return _record("edge-vocabulary", "BREAK", "unknown edge accepted")
    except gg.GuacGraphError:
        pass
    return _record("edge-vocabulary", "HELD", "11 GUAC edges, shape-checked")


def p_claim_corroboration():
    gg, _ = _module()
    if gg is None:
        return _record("claim-corroboration", "BREAK", "module absent")
    (s1, s2, s3), (v1, v2, v3) = _keys()
    g = gg.GuacGraph()
    sw = g.add_node("software", "skill-x@1.0")
    # One collector assertion: pending, excluded from blast radius.
    rec1 = g.ingest_envelope(
        gg.seal_claim(s1, "CertifyBad", "pwned", subject=sw),
        [v1, v2])
    if rec1["status"] != "pending":
        return _record("claim-corroboration", "BREAK",
                       "single claim not pending: %r" % (rec1["status"],))
    if sw in g.blast_radius(sw):
        pass  # subject is always in its own radius
    # Blast radius must NOT yet propagate to dependents of a pending claim.
    dep = g.add_node("software", "skill-y@1.0")
    g.add_edge(dep, "IsDependency", sw)
    radius = g.blast_radius(sw)
    if dep in radius:
        return _record("claim-corroboration", "BREAK",
                       "pending claim propagated")
    # Second distinct actor corroborates: verified, propagation begins.
    rec2 = g.ingest_envelope(
        gg.seal_claim(s2, "CertifyBad", "pwned", subject=sw),
        [v1, v2])
    if rec2["status"] != "verified":
        return _record("claim-corroboration", "BREAK",
                       "quorum claim not verified: %r" % (rec2["status"],))
    radius = g.blast_radius(sw)
    if dep not in radius:
        return _record("claim-corroboration", "BREAK",
                       "verified claim did not propagate")
    # Same actor asserting twice does NOT reach quorum.
    g2 = gg.GuacGraph()
    sw2 = g2.add_node("software", "skill-x@1.0")
    r = g2.ingest_envelope(
        gg.seal_claim(s3, "CertifyBad", "pwned", subject=sw2),
        [v3])
    r = g2.ingest_envelope(
        gg.seal_claim(s3, "CertifyBad", "pwned", subject=sw2),
        [v3])
    if r["status"] != "pending":
        return _record("claim-corroboration", "BREAK",
                       "same-actor double claim reached quorum")
    return _record("claim-corroboration", "HELD",
                   "pending until 2 distinct actors; same-actor no quorum")


def p_dsse_first():
    gg, _ = _module()
    if gg is None:
        return _record("dsse-first", "BREAK", "module absent")
    (s1, _s2, _s3), (v1, _v2, _v3) = _keys()
    g = gg.GuacGraph()
    sw = g.add_node("software", "skill-x@1.0")
    env = gg.seal_claim(s1, "CertifyBad", "pwned", subject=sw)
    rec = g.ingest_envelope(env, [v1])
    # The claim's evidence node is the payload digest: envelope first.
    payload_b64 = env["payload"]
    import base64
    digest = hashlib.sha256(base64.b64decode(payload_b64)).hexdigest()
    if rec["evidence_node"] != "evidence:" + digest:
        return _record("dsse-first", "BREAK",
                       "evidence node not bound to envelope payload")
    # ITE-6 layering: signatures -> actor nodes.
    if "actor:" + s1.key_id not in g.node_ids():
        return _record("dsse-first", "BREAK", "signature not mapped to actor")
    # A forged envelope is refused at ingest, never a graph node.
    bad = dict(env)
    bad["payloadType"] = "application/x-evil"
    try:
        g.ingest_envelope(bad, [v1])
        return _record("dsse-first", "BREAK",
                       "wrong payloadType accepted at ingest")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-envelope-refused":
            return _record("dsse-first", "BREAK",
                           "wrong code: %s" % exc.code)
    # Piggybacked attribution: a statement naming actor X but signed by
    # actor Y is refused.
    from gov.signing import Ed25519Signer, Ed25519Verifier
    sy = Ed25519Signer(b"\x59" * 32)
    vy = Ed25519Verifier(sy.public_key)
    from gov import dsse_envelope as _dsse
    forged_body = gg.make_claim_statement(
        "b" * 16, "CertifyBad", "evil", subject=sw)
    forged_env = _dsse.seal(forged_body, gg.GUAC_STATEMENT_PAYLOAD_TYPE,
                            [sy])
    try:
        g.ingest_envelope(forged_env, [vy])
        return _record("dsse-first", "BREAK",
                       "piggybacked attribution accepted")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-envelope-refused":
            return _record("dsse-first", "BREAK",
                           "wrong code: %s" % exc.code)
    return _record("dsse-first", "HELD",
                   "envelope-first; sig->actor; type binding enforced; "
                   "no piggybacking")


def p_blast_radius():
    gg, _ = _module()
    if gg is None:
        return _record("blast-radius", "BREAK", "module absent")
    (s1, s2, _s3), (v1, v2, _v3) = _keys()
    g = gg.GuacGraph()
    bad = g.add_node("software", "lib-evil@9.9")
    mid = g.add_node("software", "skill-mid@2.0")
    top = g.add_node("software", "agent-top@1.0")
    art = g.add_node("artifact", "c" * 64)
    g.add_edge(mid, "IsDependency", bad)
    g.add_edge(top, "IsDependency", mid)
    # IsOccurrence is a claim edge: it arrives via verified envelopes
    # (two distinct collector actors).
    for s in (s1, s2):
        g.ingest_envelope(
            gg.seal_claim(s, "IsOccurrence", "deployed here",
                          software=bad, artifact=art),
            [v1, v2])
    for s in (s1, s2):
        g.ingest_envelope(
            gg.seal_claim(s, "CertifyBad", "evil", subject=bad),
            [v1, v2])
    radius = g.blast_radius(bad)
    for want in (bad, mid, top, art):
        if want not in radius:
            return _record("blast-radius", "BREAK",
                           "missing from radius: %s" % want)
    if radius != sorted(radius):
        return _record("blast-radius", "BREAK", "radius not deterministic")
    # Cycle-safe: dependency cycle does not hang or duplicate.
    g.add_edge(bad, "IsDependency", top)
    radius2 = g.blast_radius(bad)
    if set(radius2) != set(radius):
        return _record("blast-radius", "BREAK", "cycle changed the radius")
    # Unknown node refuses loudly.
    try:
        g.blast_radius("software:nope@0.0")
        return _record("blast-radius", "BREAK", "unknown node accepted")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-unlinked":
            return _record("blast-radius", "BREAK",
                           "wrong code: %s" % exc.code)
    return _record("blast-radius", "HELD",
                   "transitive CertifyBad+IsDependency+IsOccurrence")


def p_claim_conflict():
    gg, _ = _module()
    if gg is None:
        return _record("claim-conflict", "BREAK", "module absent")
    (s1, s2, s3), (v1, v2, v3) = _keys()
    g = gg.GuacGraph()
    sw = g.add_node("software", "skill-x@1.0")
    for s in (s1, s2):
        g.ingest_envelope(
            gg.seal_claim(s, "CertifyBad", "evil", subject=sw),
            [v1, v2, v3])
    try:
        g.ingest_envelope(
            gg.seal_claim(s3, "CertifyGood", "fine", subject=sw),
            [v1, v2, v3])
        # A single CertifyGood claim is pending, not a conflict yet.
    except gg.GuacGraphError:
        return _record("claim-conflict", "BREAK",
                       "pending counter-claim raised early")
    s4 = s1  # need a second distinct CertifyGood actor; make one
    from gov.signing import Ed25519Signer, Ed25519Verifier
    s4 = Ed25519Signer(b"\x54" * 32)
    v4 = Ed25519Verifier(s4.public_key)
    g.ingest_envelope(
        gg.seal_claim(s4, "CertifyGood", "fine", subject=sw),
        [v1, v2, v3, v4])
    if sw not in g.contested():
        return _record("claim-conflict", "BREAK", "quorum conflict unflagged")
    try:
        g.blast_radius(sw)
        return _record("claim-conflict", "BREAK",
                       "blast radius walked a contested subject")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-claim-conflict":
            return _record("claim-conflict", "BREAK",
                           "wrong code: %s" % exc.code)
    return _record("claim-conflict", "HELD",
                   "quorum disagreement loud; radius refuses contested")


def p_spec_filters():
    gg, _ = _module()
    if gg is None:
        return _record("spec-filters", "BREAK", "module absent")
    (s1, s2, _s3), (v1, v2, _v3) = _keys()
    g = gg.GuacGraph()
    a1 = "actor:" + s1.key_id
    sw1 = g.add_node("software", "skill-x@1.0")
    s2n = g.add_node("software", "skill-y@1.0")
    # CertifyGood is a claim edge: verified via two collector actors.
    for s in (s1, s2):
        g.ingest_envelope(
            gg.seal_claim(s, "CertifyGood", "audited", subject=sw1),
            [v1, v2])
    g.add_edge(s2n, "IsDependency", sw1)
    hits = g.edges_with(gg.EdgeSpec(kind="CertifyGood"))
    # One row per asserting actor: (actor, kind, subject, status).
    if (len(hits) != 2 or hits[0][:2] != (a1, "CertifyGood")
            or hits[0][2] != sw1):
        return _record("spec-filters", "BREAK",
                       "EdgeSpec misfiltered: %r" % (hits,))
    hits = g.edges_with(gg.EdgeSpec(kind="IsDependency", dst=sw1))
    if len(hits) != 1 or hits[0][0] != s2n:
        return _record("spec-filters", "BREAK", "EdgeSpec dst misfiltered")
    try:
        gg.EdgeSpec(kind="CertifyBad", bogus_field="x")
        return _record("spec-filters", "BREAK", "unknown spec field accepted")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-bad-spec":
            return _record("spec-filters", "BREAK",
                           "wrong code: %s" % exc.code)
    try:
        gg.EdgeSpec(kind="NotAnEdge")
        return _record("spec-filters", "BREAK", "unknown edge kind accepted")
    except gg.GuacGraphError:
        pass
    # The GUAC-named Spec structs filter the same rows.
    hits = g.edges_with(gg.CertifyBadSpec())
    if hits:
        return _record("spec-filters", "BREAK",
                       "CertifyBadSpec matched a CertifyGood row")
    hits = g.edges_with(gg.IsOccurrenceSpec(software=s2n))
    if hits:
        return _record("spec-filters", "BREAK",
                       "IsOccurrenceSpec matched a non-occurrence row")
    return _record("spec-filters", "HELD",
                   "closed Spec structs; unknown fields refused")


def p_taxonomy_pin():
    gg, _ = _module()
    if gg is None:
        return _record("pin-taxonomy", "BREAK", "module absent")
    REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    lits = re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)
    if len(lits) != gg.TAXONOMY_PIN:
        return _record("pin-taxonomy", "BREAK",
                       "taxonomy pin drift: %d literals, want %d"
                       % (len(lits), gg.TAXONOMY_PIN))
    if len(set(lits)) != len(lits):
        return _record("pin-taxonomy", "BREAK", "duplicate literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "literals unsorted")
    _record("pin-taxonomy", "HELD", "%d/%d/0 sorted"
            % (len(lits), len(lits)))


def p_determinism():
    gg, _ = _module()
    if gg is None:
        return _record("determinism", "BREAK", "module absent")
    (s1, s2, _s3), (v1, v2, _v3) = _keys()
    def _build():
        g = gg.GuacGraph()
        sw = g.add_node("software", "skill-x@1.0")
        g.add_node("actor", "a" * 16)
        g.ingest_envelope(
            gg.seal_claim(s2, "CertifyBad", "evil", subject=sw),
            [v1, v2])
        g.ingest_envelope(
            gg.seal_claim(s1, "CertifyBad", "evil", subject=sw),
            [v1, v2])
        return g
    g1, g2 = _build(), _build()
    if g1.digest() != g2.digest():
        return _record("determinism", "BREAK", "digest order-dependent")
    if g1.serialize() != g2.serialize():
        return _record("determinism", "BREAK", "serialize order-dependent")
    g3 = _build()
    r = json.loads(g3.serialize())
    if r.get("schema_version") != 1:
        return _record("determinism", "BREAK", "schema version not sealed")
    return _record("determinism", "HELD", "insertion-order independent")


def p_bounds():
    gg, _ = _module()
    if gg is None:
        return _record("bounds", "BREAK", "module absent")
    g = gg.GuacGraph(max_nodes=2)
    g.add_node("actor", "a" * 16)
    g.add_node("actor", "b" * 16)
    try:
        g.add_node("actor", "c" * 16)
        return _record("bounds", "BREAK", "node cap not enforced")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-overflow":
            return _record("bounds", "BREAK", "wrong code: %s" % exc.code)
    return _record("bounds", "HELD", "finite caps fail closed")


def p_ingest_strictness():
    gg, _ = _module()
    if gg is None:
        return _record("ingest-strictness", "BREAK", "module absent")
    (s1, _s2, _s3), (v1, _v2, _v3) = _keys()
    g = gg.GuacGraph()
    sw = g.add_node("software", "skill-x@1.0")
    # Extra field inside the claim object: refused, not silently dropped.
    env = gg.seal_claim(s1, "CertifyBad", "evil", subject=sw)
    payload, payload_type, _ = gg._dsse.parse_envelope(env)
    body = json.loads(payload.decode("utf-8"))
    body["claim"]["extra_field"] = "smuggle"
    env2 = gg._dsse.seal(json.dumps(body, sort_keys=True).encode("utf-8"),
                         payload_type, [s1])
    try:
        g.ingest_envelope(env2, [v1])
        return _record("ingest-strictness", "BREAK",
                       "extra claim field accepted")
    except gg.GuacGraphError as exc:
        if exc.code != "guac-graph-envelope-refused":
            return _record("ingest-strictness", "BREAK",
                           "wrong code: %s" % exc.code)
    # threshold != 1 is refused: quorum is one-envelope-per-actor.
    env = gg.seal_claim(s1, "CertifyBad", "evil", subject=sw)
    for bad_t in (0, 2):
        try:
            g.ingest_envelope(env, [v1], threshold=bad_t)
            return _record("ingest-strictness", "BREAK",
                           "threshold=%r accepted" % bad_t)
        except gg.GuacGraphError as exc:
            if exc.code != "guac-graph-malformed":
                return _record("ingest-strictness", "BREAK",
                               "wrong code: %s" % exc.code)
    return _record("ingest-strictness", "HELD",
                   "claim-level fields closed; threshold pinned at 1")


def _green_check():
    if SKIP_GREEN:
        return
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    target = os.path.join(here, "w250_evidence_graph_probes.py")
    r = subprocess.run([sys.executable, target], cwd=repo, env=env,
                       capture_output=True, text=True, timeout=600)
    out = (r.stdout or "") + (r.stderr or "")
    if r.returncode != 0 or "BREAK" in out.splitlines()[-40:]:
        _record("green-adjacent-evidence-graph", "BREAK",
                "adjacent battery red: rc=%d" % r.returncode)


def main():
    for probe in (p_module_absent, p_schema_pinned, p_triad_ontology,
                  p_edge_vocabulary, p_claim_corroboration, p_dsse_first,
                  p_blast_radius, p_claim_conflict, p_spec_filters,
                  p_taxonomy_pin, p_determinism, p_bounds,
                  p_ingest_strictness):
        try:
            probe()
        except Exception as exc:  # noqa: BLE001 - a probe must never die
            _record(probe.__name__, "ERROR", "%r" % (exc,))
    _green_check()
    n_break = sum(1 for r in RESULTS if r["verdict"] == "BREAK")
    n_held = sum(1 for r in RESULTS if r["verdict"] == "HELD")
    n_err = sum(1 for r in RESULTS if r["verdict"] == "ERROR")
    for r in RESULTS:
        print("%-28s %-6s %s" % (r["probe"], r["verdict"], r["detail"]))
    print("== %d BREAK / %d HELD / %d ERROR ==" % (n_break, n_held, n_err))
    return 1 if (n_break or n_err) else 0


if __name__ == "__main__":
    sys.exit(main())
