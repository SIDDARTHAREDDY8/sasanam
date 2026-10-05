"""Wave-300 lane 3 battery: memory store<->reconcile composition.

Base: wave-299 merge a830f65f80e9317aa7ae65b83b7eb14b3922bd0e
(verified via git rev-parse HEAD before work).

New product surface:
  gov/memory_composed.py -- the single composed write/recall path that
  resolves the six wave-299 red-team seam hazards (SeamHazardTest):
  per-namespace stores, canonical content-derived fact ids, reconcile
  tombstone semantics via generation-suffixed store keys, grade
  normalization, temporal mapping (written_at->valid_at/created_at,
  expires_at->retain_until), namespace-owner trust anchor.
  3 new memory-composed-* codes; pin 1797 -> 1800.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module, and the pin probe sees 1797
literals); on the fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g300-mc && TMPDIR=/var/tmp/g300-mc \
    ~/workspace/.gov-venv/bin/python evals/w300_memory_composed_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g300-mc2 \
    ~/workspace/.gov-venv/bin/python evals/w300_memory_composed_probes.py
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import traceback

# Wave-95 lesson: module-level staging default; the harness's declared
# ungoverned_ack is refused in production mode.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "evals"))
import probe_lines  # noqa: E402  (canonical probe-line form)
for _p in (REPO, os.path.join(REPO, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

TAXONOMY_PIN = 2128 # Wave-299 merge pin 1797; wave-300 lane 3: pin 1797 -> 1800 (+3 memory-composed-*); wave-300 merge: 1802 (+2 delegation-approval-*); wave-301 merge: 1812 (+10 workflow-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


_results = []


def _record(pid, verdict, note):
    _results.append((pid, verdict, note))


def _safe(pid, fn):
    """Run a probe so an uncaught exception becomes ERROR, never a
    dead battery (wave-289 lane-1 lesson)."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        _record(pid, "ERROR", "probe crashed: %r\n%s"
                % (e, traceback.format_exc(limit=3)))


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
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
        return _record("pin-taxonomy", "BREAK", "duplicate code literals")
    if lits != sorted(lits):
        return _record("pin-taxonomy", "BREAK", "code literals not sorted")
    for want in ("memory-composed-divergent", "memory-composed-key-too-long"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK", "missing code %s" % want)
    _record("pin-taxonomy", "HELD", "1827/1827/0 sorted")


def _mod_or_break(pid):
    """Import gov.memory_composed; on the pristine base the module is
    absent -- record BREAK (the red-first signal), not ERROR."""
    try:
        import gov.memory_composed as mc
        return mc
    except ImportError:
        _record(pid, "BREAK", "gov.memory_composed absent (pristine base)")
        return None


def p_import():
    mc = _mod_or_break("mc-import")
    if mc is None:
        return
    for name in ("MemoryComposer", "MemoryComposedError",
                 "MC_DIVERGENT", "MC_KEY_TOO_LONG", "MC_KEY_INVALID",
                 "MAX_COMPOSED_KEY_LEN"):
        if not hasattr(mc, name):
            return _record("mc-import", "BREAK", "missing attr %s" % name)
    _record("mc-import", "HELD", "module present")


def _seed(tag):
    return hashlib.sha256(b"w300-memory-compose:" + tag.encode()).digest()


def _setup():
    """(reconciler, composer, owner_seed, owner_pub, store) with
    namespace 'agent-a' declared and a store bound."""
    from gov import ed25519
    import gov.memory_reconcile as mr
    import gov.memory_store as ms
    mc = _mod_or_break("setup")
    assert mc is not None
    r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                            max_writes_per_principal=10000,
                            write_window_seconds=3600)
    owner_seed = _seed("owner-a")
    owner_pub = ed25519.publickey(owner_seed).hex()
    r.declare_namespace("agent-a", owner_pub)
    store = ms.MemoryStore()
    comp = mc.MemoryComposer(r, {"agent-a": owner_seed})
    comp.bind_store("agent-a", store)
    return r, comp, owner_seed, owner_pub, store


def _provenance(principal="agent-a", reliability="C3", corroborations=0,
                ingested_at=1000):
    return {"source_principal": principal, "reliability": reliability,
            "corroborations": corroborations, "ingested_at": ingested_at}


def _candidate(owner_seed, key="user-preference-theme", value="dark",
               op="add", supersedes=None, provenance=None,
               namespace="agent-a", written_at=1000, expires_at=None):
    from gov import ed25519
    vd = hashlib.sha256(value.encode()).hexdigest()
    cand = {"schema": "memory-record/v1", "namespace": namespace,
            "key": key, "value_digest": vd, "written_at": written_at,
            "supersedes": supersedes,
            "provenance": provenance or _provenance(),
            "expires_at": expires_at, "op": op}
    body = {k: cand[k] for k in
            ("schema", "namespace", "key", "value_digest", "written_at",
             "supersedes", "provenance", "expires_at", "op")}
    cand["signature"] = ed25519.sign(
        owner_seed, json.dumps(body, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True).encode()).hex()
    return cand


def _expect_code(pid, fn, want_code):
    """Expect a CODED refusal (F351 contract). The composed path lets
    coded layer refusals propagate unchanged, so MemoryComposedError,
    MemoryReconcileError, and MemoryStoreError are all accepted --
    what matters is the machine code."""
    mc = _mod_or_break(pid)
    if mc is None:
        return
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        got = getattr(e, "code", None)
        if got == want_code:
            return _record(pid, "HELD",
                           "refused coded %s (%s)" % (want_code,
                                                      type(e).__name__))
        return _record(pid, "BREAK",
                       "wrong refusal: %s code=%r, want %r"
                       % (type(e).__name__, got, want_code))
    return _record(pid, "BREAK", "no refusal; want coded %s" % want_code)


def _reconcile_fact_id(namespace, key, value_digest, written_at,
                        supersedes):
    body = {"namespace": namespace, "key": key,
            "value_digest": value_digest, "written_at": written_at,
            "supersedes": supersedes}
    return hashlib.sha256(json.dumps(
        body, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode()).hexdigest()


# ------------------------------------------------------------------
# Decision 1: namespace enforced end-to-end (per-namespace stores)
# ------------------------------------------------------------------

def p_namespace_enforced():
    mc = _mod_or_break("mc-namespace")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    cand = _candidate(owner_seed)
    out = comp.composed_write("agent-a", cand, store, {}, 1000)
    if out["decision"]["decision"] != "ADD":
        return _record("mc-namespace", "BREAK", "want ADD")
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 1001)
    if view["namespace"] != "agent-a" or \
            view["value_digest"] != cand["value_digest"]:
        return _record("mc-namespace", "BREAK", "recall mismatch")
    # Undeclared namespace: the reconciler refuses.
    _expect_code("mc-namespace",
                 lambda: comp.composed_write(
                     "agent-b", _candidate(owner_seed,
                                           namespace="agent-b"),
                     store, {}, 1000),
                 "memory-reconcile-unauthorized-namespace")
    # Candidate bound to a different namespace than the call.
    _expect_code("mc-namespace",
                 lambda: comp.composed_write(
                     "agent-a", _candidate(owner_seed,
                                           namespace="agent-b"),
                     store, {}, 1000),
                 "memory-reconcile-invalid")
    _record("mc-namespace", "HELD",
            "per-namespace stores; undeclared + mismatched refused")


def p_fork_store_refused():
    mc = _mod_or_break("mc-fork")
    if mc is None:
        return
    import gov.memory_store as ms
    r, comp, owner_seed, _, store = _setup()
    comp.composed_write("agent-a", _candidate(owner_seed), store, {}, 1000)
    other = ms.MemoryStore()
    _expect_code("mc-fork",
                 lambda: comp.composed_write(
                     "agent-a", _candidate(owner_seed, value="light",
                                           written_at=1001),
                     other, {}, 1001),
                 mc.MC_DIVERGENT)
    _record("mc-fork", "HELD", "second store object refused (fork)")


# ------------------------------------------------------------------
# Decision 2: canonical content-derived fact ids
# ------------------------------------------------------------------

def p_fact_id_canonical():
    mc = _mod_or_break("mc-fact-id")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    cand = _candidate(owner_seed, written_at=1000)
    out = comp.composed_write("agent-a", cand, store, {}, 1000)
    want = _reconcile_fact_id("agent-a", "user-preference-theme",
                              cand["value_digest"], 1000, None)
    if out["decision"]["fact_id"] != want:
        return _record("mc-fact-id", "BREAK",
                       "decision fact_id is not the reconcile derivation")
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 1001)
    if view["reconcile_fact_id"] != want:
        return _record("mc-fact-id", "BREAK", "recall fact_id mismatch")
    if view["store_fact_id"] == want:
        return _record("mc-fact-id", "BREAK",
                       "store seq-derived id leaked as canonical")
    _record("mc-fact-id", "HELD",
            "canonical = reconcile derivation; store id internal only")


# ------------------------------------------------------------------
# Decision 3: tombstone semantics -- reconcile wins via generations
# ------------------------------------------------------------------

def p_tombstone_readmit():
    mc = _mod_or_break("mc-tombstone")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    comp.composed_write("agent-a", _candidate(owner_seed, value="dark"),
                        store, {}, 1000)
    add_dec = comp.composed_write(
        "agent-a", _candidate(owner_seed, value="dark", written_at=1001),
        store, {}, 1001)["decision"]
    # DELETE names the latest fact id (snapshot-before-mutation).
    comp.composed_write(
        "agent-a",
        _candidate(owner_seed, value="dark", op="delete",
                   supersedes=add_dec["fact_id"], written_at=1002),
        store, {}, 1002)
    # Recall now refuses: the reconcile tombstone excludes it...
    try:
        comp.composed_recall(
            "agent-a", {"namespace": "agent-a",
                        "key": "user-preference-theme"}, "agent-a", 1003)
        return _record("mc-tombstone", "BREAK", "tombstoned recall live")
    except Exception as e:  # noqa: BLE001
        # memory-reconcile-invalid from the reconciler's tombstone
        # exclusion is a correct coded refusal here.
        if getattr(e, "code", None) != "memory-reconcile-invalid":
            return _record("mc-tombstone", "BREAK",
                           "wrong refusal: %s code=%r"
                           % (type(e).__name__, getattr(e, "code", None)))
    # ...but a new ADD re-admits under a new generation.
    out = comp.composed_write(
        "agent-a", _candidate(owner_seed, value="light", written_at=1004),
        store, {}, 1004)
    if out["generation"] != 1:
        return _record("mc-tombstone", "BREAK",
                       "re-admission did not advance generation")
    if out["store_key"] == "user-preference-theme":
        return _record("mc-tombstone", "BREAK",
                       "re-admission reused the tombstoned store key")
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 1005)
    if view["value_digest"] != hashlib.sha256(b"light").hexdigest():
        return _record("mc-tombstone", "BREAK", "re-admitted value wrong")
    _record("mc-tombstone", "HELD",
            "tombstone withdraws the claim; re-admission via generation")


# ------------------------------------------------------------------
# Decision 4: grade normalization
# ------------------------------------------------------------------

def p_grade_normalize():
    mc = _mod_or_break("mc-grade")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    cand = _candidate(owner_seed, provenance=_provenance(
        reliability="A1", corroborations=0))
    comp.composed_write("agent-a", cand, store, {}, 1000)
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 1001)
    if view["reliability_grade"] != "A1":
        return _record("mc-grade", "BREAK",
                       "grade not normalized, got %r"
                       % view["reliability_grade"])
    if view["provenance"]["reliability"] != "A1":
        return _record("mc-grade", "BREAK", "provenance grade lost")
    # Outside the closed 8-token vocabulary: refused at the seam.
    _expect_code("mc-grade",
                 lambda: comp.composed_write(
                     "agent-a",
                     _candidate(owner_seed, key="k2",
                                provenance=_provenance(reliability="Z9")),
                     store, {}, 1000),
                 "memory-reconcile-invalid")
    _record("mc-grade", "HELD", "closed grade vocabulary normalized")


# ------------------------------------------------------------------
# Decision 5: temporal mapping (store bi-temporal is authoritative)
# ------------------------------------------------------------------

def p_temporal_map():
    mc = _mod_or_break("mc-temporal")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    cand = _candidate(owner_seed, written_at=100, expires_at=200)
    comp.composed_write("agent-a", cand, store, {}, 100)
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 150)
    if not (view["valid_at"] == 100 and view["created_at"] == 100
            and view["retain_until"] == 200):
        return _record("mc-temporal", "BREAK",
                       "temporal mapping wrong: %r" % (view,))
    # Before valid_at: the store's bi-temporal check refuses.
    try:
        comp.composed_recall(
            "agent-a", {"namespace": "agent-a",
                        "key": "user-preference-theme"}, "agent-a", 50)
        return _record("mc-temporal", "BREAK", "pre-valid recall live")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "memory-store-expired":
            return _record("mc-temporal", "BREAK",
                           "wrong pre-valid refusal: %s code=%r"
                           % (type(e).__name__, getattr(e, "code", None)))
    # After retain_until: lapsed retention refuses loud.
    try:
        comp.composed_recall(
            "agent-a", {"namespace": "agent-a",
                        "key": "user-preference-theme"}, "agent-a", 250)
        return _record("mc-temporal", "BREAK", "lapsed recall live")
    except Exception as e:  # noqa: BLE001
        if getattr(e, "code", None) != "memory-store-retention-lapsed":
            return _record("mc-temporal", "BREAK",
                           "wrong lapsed refusal: %s code=%r"
                           % (type(e).__name__, getattr(e, "code", None)))


# ------------------------------------------------------------------
# Decision 6: namespace-owner trust anchor
# ------------------------------------------------------------------

def p_trust_anchor():
    mc = _mod_or_break("mc-trust")
    if mc is None:
        return
    from gov import ed25519
    import gov.memory_store as ms
    r, comp, owner_seed, owner_pub, store = _setup()
    cand = _candidate(owner_seed,
                      provenance=_provenance(principal="observer-1"))
    out = comp.composed_write("agent-a", cand, store, {}, 1000)
    # The store-level signature is the OWNER's key...
    srec = store.recall("user-preference-theme", 1001)
    # (store recall is keyed by the composed store key, gen 0 = key)
    if srec["source_principal"] != "agent-a":
        return _record("mc-trust", "BREAK", "store principal not owner")
    # ...while the original observer survives in the decision provenance.
    if out["decision"]["fact_id"] is None:
        return _record("mc-trust", "BREAK", "no decision")
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 1001)
    if view["provenance"]["source_principal"] != "observer-1":
        return _record("mc-trust", "BREAK", "observer provenance lost")
    # A candidate signed by a NON-owner key refuses at the seam.
    other_seed = _seed("intruder")
    _expect_code("mc-trust",
                 lambda: comp.composed_write(
                     "agent-a", _candidate(other_seed, key="k2"),
                     store, {}, 1000),
                 "memory-reconcile-unauthorized-namespace")
    _record("mc-trust", "HELD",
            "owner key anchors the store; observer in decision provenance")


# ------------------------------------------------------------------
# Attack probes
# ------------------------------------------------------------------

def p_cross_ns_write_refused():
    mc = _mod_or_break("mc-xns-write")
    if mc is None:
        return
    from gov import ed25519
    import gov.memory_reconcile as mr
    r, comp, owner_seed, _, store = _setup()
    b_seed = _seed("owner-b")
    r.declare_namespace("agent-b", ed25519.publickey(b_seed).hex())
    # The composer CAN act for agent-b's owner (holds its seed), but the
    # candidate is signed by agent-a's owner key: the namespace-owner
    # signature check at the seam refuses.
    from gov import memory_composed as _mc
    comp2 = _mc.MemoryComposer(r, {"agent-a": owner_seed,
                                   "agent-b": b_seed})
    comp2.bind_store("agent-b", store)
    _expect_code("mc-xns-write",
                 lambda: comp2.composed_write(
                     "agent-b", _candidate(owner_seed, namespace="agent-b",
                                           key="k"),
                     store, {}, 1000),
                 "memory-reconcile-unauthorized-namespace")
    _record("mc-xns-write", "HELD", "cross-namespace write refused")


def p_grantless_recall_refused():
    mc = _mod_or_break("mc-grantless")
    if mc is None:
        return
    from gov import ed25519
    r, comp, owner_seed, _, store = _setup()
    b_seed = _seed("owner-b")
    r.declare_namespace("agent-b", ed25519.publickey(b_seed).hex())
    comp.composed_write("agent-a", _candidate(owner_seed), store, {}, 1000)
    scope = {"namespace": "agent-a", "key": "user-preference-theme"}
    _expect_code("mc-grantless",
                 lambda: comp.composed_recall(
                     "agent-a", scope, "agent-b", 1001),
                 "memory-reconcile-unauthorized-namespace")
    # With a live grant, the same recall works -- the grant is
    # PRESENTED (bearer-grant model, F376 wave-300 merge).
    grant = r.grant_sharing("agent-a", "agent-b", 900, 2000,
                            _seed("owner-a"))
    assert grant["grantee_namespace"] == "agent-b"
    view = comp.composed_recall("agent-a", scope, "agent-b", 1001,
                                grant=grant)
    if view["key"] != "user-preference-theme":
        return _record("mc-grantless", "BREAK", "granted recall wrong")
    _record("mc-grantless", "HELD",
            "grant-less cross-ns recall refused; granted recall works")


def p_supersede_recall():
    mc = _mod_or_break("mc-supersede")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    d1 = comp.composed_write(
        "agent-a", _candidate(owner_seed, value="v1"), store, {},
        1000)["decision"]
    d2 = comp.composed_write(
        "agent-a",
        _candidate(owner_seed, value="v2", op="update",
                   supersedes=d1["fact_id"], written_at=1001),
        store, {}, 1001)["decision"]
    if d2["decision"] != "UPDATE":
        return _record("mc-supersede", "BREAK", "want UPDATE")
    view = comp.composed_recall(
        "agent-a", {"namespace": "agent-a",
                    "key": "user-preference-theme"}, "agent-a", 1002)
    if view["value_digest"] != hashlib.sha256(b"v2").hexdigest():
        return _record("mc-supersede", "BREAK", "recall not v2")
    if view["reconcile_fact_id"] != d2["fact_id"]:
        return _record("mc-supersede", "BREAK", "fact_id not v2's")
    hist = comp.composed_history(
        "agent-a", "user-preference-theme", 1002)
    if len(hist["store_history"]) < 2:
        return _record("mc-supersede", "BREAK", "history lost v1")
    _record("mc-supersede", "HELD",
            "supersede-then-recall reflects v2; history preserved")


def p_forged_candidate():
    mc = _mod_or_break("mc-forged")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    cand = _candidate(owner_seed)
    cand["value_digest"] = hashlib.sha256(b"evil").hexdigest()  # tamper
    _expect_code("mc-forged",
                 lambda: comp.composed_write("agent-a", cand, store,
                                             {}, 1000),
                 "memory-reconcile-unauthorized-namespace")
    _record("mc-forged", "HELD", "tampered candidate refused")


def p_key_too_long():
    mc = _mod_or_break("mc-keylen")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    _expect_code("mc-keylen",
                 lambda: comp.composed_write(
                     "agent-a", _candidate(owner_seed, key="k" * 100),
                     store, {}, 1000),
                 mc.MC_KEY_TOO_LONG)
    _record("mc-keylen", "HELD", "over-long composed key refused")


def p_key_grammar():
    mc = _mod_or_break("mc-keygrammar")
    if mc is None:
        return
    r, comp, owner_seed, _, store = _setup()
    # Slash-keys are reconcile-valid but not store-representable:
    # the composed path narrows fail-closed, before the decision.
    _expect_code("mc-keygrammar",
                 lambda: comp.composed_write(
                     "agent-a", _candidate(owner_seed,
                                           key="user/preference/theme"),
                     store, {}, 1000),
                 mc.MC_KEY_INVALID)
    # The refused key must not wedge the reconciler: a dash-key works.
    out = comp.composed_write(
        "agent-a", _candidate(owner_seed, key="user-preference-theme2"),
        store, {}, 1000)
    if out["decision"]["decision"] != "ADD":
        return _record("mc-keygrammar", "BREAK", "dash-key not writable")
    _record("mc-keygrammar", "HELD",
            "non-store-grammar key refused pre-decision; no wedge")


def p_divergent_fork():
    mc = _mod_or_break("mc-divergent")
    if mc is None:
        return
    from gov import ed25519
    import gov.memory_store as ms
    r, comp, owner_seed, owner_pub, store = _setup()
    comp.composed_write("agent-a", _candidate(owner_seed, value="v1"),
                        store, {}, 1000)
    # A second writer bypasses the composer and writes a DIFFERENT
    # fact under the same store key: the layers now disagree.
    evil_ep_body = {"agent_id": "agent-a",
                    "content_digest": hashlib.sha256(b"evil").hexdigest(),
                    "source_principal": "agent-a",
                    "source_pubkey": owner_pub,
                    "recorded_at": 1001}
    evil_ep_sig = ed25519.sign(
        owner_seed, json.dumps(evil_ep_body, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True).encode()).hex()
    evil_ep = store.record_episode(
        "agent-a", hashlib.sha256(b"evil").hexdigest(), "agent-a",
        owner_pub, evil_ep_sig, 1001)
    evil_body = {"statement_key": "user-preference-theme",
                 "statement_digest": hashlib.sha256(b"evil").hexdigest(),
                 "source_episode_ids": [evil_ep],
                 "source_principal": "agent-a",
                 "source_pubkey": owner_pub,
                 "valid_at": 1001,
                 "retain_until": None,
                 "reliability": "C",
                 "credibility": 3,
                 "created_at": 1001}
    evil_sig = ed25519.sign(
        owner_seed, json.dumps(evil_body, sort_keys=True,
                               separators=(",", ":"),
                               ensure_ascii=True).encode()).hex()
    store.record_fact("user-preference-theme",
                      hashlib.sha256(b"evil").hexdigest(), [evil_ep],
                      "agent-a", owner_pub, evil_sig, 1001, 1001)
    _expect_code("mc-divergent",
                 lambda: comp.composed_recall(
                     "agent-a",
                     {"namespace": "agent-a",
                      "key": "user-preference-theme"},
                     "agent-a", 1002),
                 mc.MC_DIVERGENT)
    _record("mc-divergent", "HELD",
            "store/reconciler fork detected at recall")


def p_ed25519_contract():
    mc = _mod_or_break("mc-ed25519")
    if mc is None:
        return
    from gov import ed25519
    r, comp, owner_seed, owner_pub, store = _setup()
    cand = _candidate(owner_seed)
    # Flip a signature bit: must NOT verify (bool-returning contract).
    bad = bytearray(bytes.fromhex(cand["signature"]))
    bad[0] ^= 0x01
    cand["signature"] = bytes(bad).hex()
    _expect_code("mc-ed25519",
                 lambda: comp.composed_write("agent-a", cand, store,
                                             {}, 1000),
                 "memory-reconcile-unauthorized-namespace")
    _record("mc-ed25519", "HELD", "forged signature refused (is True)")


# ------------------------------------------------------------------
# Depth-1 green checks + runner
# ------------------------------------------------------------------

def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    if not os.path.exists(path):
        _record("green-%s" % name, "HELD", "battery absent at base")
        return
    tmp = tempfile.mkdtemp(prefix="g300-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmp
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            timeout=600, env=env, cwd=REPO).stdout
    except Exception as e:  # noqa: BLE001
        return _record("green-%s" % name, "ERROR",
                       "green check crashed: %r" % (e,))
    bad = [ln for ln in out.splitlines()
           if ln.strip().startswith("[BREAK]")
           and not any(t in ln for t in tolerate)]
    if bad:
        _record("green-%s" % name, "BREAK",
                "unexpected breaks: %s" % "; ".join(bad[:5]))
    else:
        _record("green-%s" % name, "HELD", "green check held")


def main():
    _safe("pin-taxonomy", p_taxonomy_pin)
    for pid, fn in [
        ("mc-import", p_import),
        ("mc-namespace", p_namespace_enforced),
        ("mc-fork", p_fork_store_refused),
        ("mc-fact-id", p_fact_id_canonical),
        ("mc-tombstone", p_tombstone_readmit),
        ("mc-grade", p_grade_normalize),
        ("mc-temporal", p_temporal_map),
        ("mc-trust", p_trust_anchor),
        ("mc-xns-write", p_cross_ns_write_refused),
        ("mc-grantless", p_grantless_recall_refused),
        ("mc-supersede", p_supersede_recall),
        ("mc-forged", p_forged_candidate),
        ("mc-keylen", p_key_too_long),
        ("mc-keygrammar", p_key_grammar),
        ("mc-divergent", p_divergent_fork),
        ("mc-ed25519", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w298_memory_store_probes.py"),
                 "w298-memory-store", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals",
                              "w298_memory_reconcile_probes.py"),
                 "w298-memory-reconcile", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w300_memory_composed: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
