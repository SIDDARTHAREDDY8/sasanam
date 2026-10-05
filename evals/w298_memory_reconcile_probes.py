"""Wave-298 lane 3 battery: memory reconciliation seam + poisoning defenses.

Base: wave-297 merge 5662f8874b63724a1bfd1f4441b470bfe1ba43d8
(verified via git rev-parse HEAD before work).

New product surface:
  (a) gov/memory_reconcile.py -- ADD/UPDATE/DELETE/NOOP reconciliation
      seam (mem0 pattern), per-agent namespacing with sharing grants,
      qdrant poisoning-defense checklist (payload metadata, mandatory
      scope predicate, snapshot-before-mutation, tombstones excluded
      from recall, write-rate bound, conflict-evidence requirement);
  (b) 5 new memory-reconcile-* decision codes at true sorted positions;
      lane pin 1769 -> 1774; wave-298 merge: pin 1774 -> 1780.

Red-first: on the pristine base the new-API probes BREAK (feature
absent: ImportError on the new module, and the pin probe sees 1769
literals); on the fixed tree they must HELD with loud coded refusals.

Run:
  mkdir -p /var/tmp/g298-mr && TMPDIR=/var/tmp/g298-mr \
    ~/workspace/.gov-venv/bin/python evals/w298_memory_reconcile_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g298-mr2 \
    ~/workspace/.gov-venv/bin/python evals/w298_memory_reconcile_probes.py
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

TAXONOMY_PIN = 2127 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable). Wave-297 merge pin 1769; wave-298 lane 3: pin 1769 -> 1774 (+5 memory-reconcile-*); wave-298 merge: pin 1774 -> 1780 (+11 codes); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


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
    for want in ("memory-reconcile-invalid", "memory-reconcile-scope-missing",
                 "memory-reconcile-unauthorized-namespace",
                 "memory-reconcile-poison-refused",
                 "memory-reconcile-conflict-unresolved"):
        if want not in lits:
            return _record("pin-taxonomy", "BREAK", "missing code %s" % want)
    _record("pin-taxonomy", "HELD", "2127/2127/0 sorted")




def _mod():
    import gov.memory_reconcile as mr
    return mr


def p_import():
    try:
        mr = _mod()
    except ImportError:
        return _record("mr-import", "BREAK", "gov.memory_reconcile absent")
    for name in ("MemoryReconciler", "MemoryReconcileError", "RC_ADD",
                 "RC_UPDATE", "RC_DELETE", "RC_NOOP", "RC_INVALID",
                 "RC_SCOPE_MISSING", "RC_UNAUTH_NS", "RC_POISON",
                 "RC_CONFLICT"):
        if not hasattr(mr, name):
            return _record("mr-import", "BREAK", "missing attr %s" % name)
    _record("mr-import", "HELD", "module present")


def _seed(tag):
    return hashlib.sha256(b"w298-memory-reconcile:" + tag.encode()).digest()


def _setup():
    """(reconciler, owner_seed, owner_pubkey_hex) with namespace
    'agent-a' declared."""
    from gov import ed25519
    mr = _mod()
    r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                            max_writes_per_principal=10000,
                            write_window_seconds=3600)
    owner_seed = _seed("owner-a")
    owner_pub = ed25519.publickey(owner_seed).hex()
    r.declare_namespace("agent-a", owner_pub)
    return r, owner_seed, owner_pub


def _provenance(principal="agent-a", reliability="C3", corroborations=0,
                ingested_at=1000):
    return {"source_principal": principal, "reliability": reliability,
            "corroborations": corroborations, "ingested_at": ingested_at}


def _candidate(r, owner_seed, key="user/preference/theme",
               value="dark", op="add", supersedes=None,
               provenance=None, namespace="agent-a", written_at=1000,
               expires_at=None):
    from gov import ed25519
    mr = _mod()
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
    from gov import memory_reconcile as mr
    try:
        fn()
    except mr.MemoryReconcileError as e:
        if e.code == want_code:
            return _record(pid, "HELD", "refused coded %s" % want_code)
        return _record(pid, "BREAK",
                       "wrong code: got %r, want %r" % (e.code, want_code))
    return _record(pid, "BREAK", "no refusal; want coded %s" % want_code)


def p_add():
    mr = _mod()
    r, owner_seed, _ = _setup()
    cand = _candidate(r, owner_seed)
    dec = r.reconcile(cand, [], {}, 1000)
    if dec["decision"] != mr.RC_ADD:
        return _record("mr-add", "BREAK", "want ADD, got %r"
                       % dec["decision"])
    if not r.verify_decision(dec):
        return _record("mr-add", "BREAK", "decision does not re-verify")
    rec = r.recall({"namespace": "agent-a", "key": "user/preference/theme"},
                   "agent-a", 1001)
    if rec["state"] != "active":
        return _record("mr-add", "BREAK", "recalled record not active")
    _record("mr-add", "HELD", "ADD + verify + recall round-trip")


def p_noop():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    hist = [r.recall({"namespace": "agent-a",
                      "key": "user/preference/theme"}, "agent-a", 1001)]
    dec = r.reconcile(_candidate(r, owner_seed, written_at=1002),
                      hist, {}, 1002)
    if dec["decision"] != mr.RC_NOOP:
        return _record("mr-noop", "BREAK", "want NOOP, got %r"
                       % dec["decision"])
    _record("mr-noop", "HELD", "duplicate write -> NOOP")


def p_update_corborated():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(
        r, owner_seed,
        provenance=_provenance(reliability="A1", corroborations=3)), [],
        {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    upd = _candidate(r, owner_seed, value="light", op="update",
                     supersedes=latest["fact_id"],
                     provenance=_provenance(reliability="C3",
                                            corroborations=2),
                     written_at=1002)
    dec = r.reconcile(upd, [latest], {}, 1002)
    if dec["decision"] != mr.RC_UPDATE:
        return _record("mr-update-corroborated", "BREAK",
                       "want UPDATE, got %r" % dec["decision"])
    if dec["supersedes"] != latest["fact_id"] or not dec["snapshot_digest"]:
        return _record("mr-update-corroborated", "BREAK",
                       "missing supersedes/snapshot")
    if not r.verify_decision(dec):
        return _record("mr-update-corroborated", "BREAK",
                       "decision does not re-verify")
    _record("mr-update-corroborated", "HELD",
            "corroborated UPDATE supersedes with snapshot")


def p_update_poison_refused():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(
        r, owner_seed,
        provenance=_provenance(reliability="A1", corroborations=3)), [],
        {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    upd = _candidate(r, owner_seed, value="light", op="update",
                     supersedes=latest["fact_id"],
                     provenance=_provenance(reliability="C3",
                                            corroborations=0),
                     written_at=1002)
    _expect_code("mr-poison-refused",
                 lambda: r.reconcile(upd, [latest], {}, 1002),
                 mr.RC_POISON)


def p_update_archivist_override():
    from gov import ed25519
    mr = _mod()
    r, owner_seed, _ = _setup()
    arch_seed = _seed("archivist")
    r.declare_archivist(ed25519.publickey(arch_seed).hex())
    r.reconcile(_candidate(
        r, owner_seed,
        provenance=_provenance(reliability="B2", corroborations=3)), [],
        {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    upd = _candidate(r, owner_seed, value="light", op="update",
                     supersedes=latest["fact_id"],
                     provenance=_provenance(reliability="C3",
                                            corroborations=0),
                     written_at=1002)
    body = {k: upd[k] for k in
            ("schema", "namespace", "key", "value_digest", "written_at",
             "supersedes", "provenance", "expires_at", "op")}
    override = ed25519.sign(
        arch_seed, json.dumps(body, sort_keys=True,
                              separators=(",", ":"),
                              ensure_ascii=True).encode()).hex()
    dec = r.reconcile(upd, [latest], {"archivist_override": override},
                      1002)
    if dec["decision"] != mr.RC_UPDATE:
        return _record("mr-archivist-override", "BREAK",
                       "want UPDATE, got %r" % dec["decision"])
    _record("mr-archivist-override", "HELD",
            "signed archivist override permits contradiction")


def p_update_no_supersedes():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    upd = _candidate(r, owner_seed, value="light", op="update",
                     supersedes=None, written_at=1002)
    _expect_code("mr-update-no-snapshot",
                 lambda: r.reconcile(upd, [latest], {}, 1002),
                 mr.RC_INVALID)


def p_add_conflict():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    dup = _candidate(r, owner_seed, value="light", op="add",
                     written_at=1002)
    _expect_code("mr-add-conflict",
                 lambda: r.reconcile(dup, [latest], {}, 1002),
                 mr.RC_CONFLICT)


def p_delete_tombstones():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    dele = _candidate(r, owner_seed, op="delete",
                      supersedes=latest["fact_id"], written_at=1002)
    dec = r.reconcile(dele, [latest], {}, 1002)
    if dec["decision"] != mr.RC_DELETE:
        return _record("mr-delete", "BREAK", "want DELETE, got %r"
                       % dec["decision"])
    if not dec["snapshot_digest"]:
        return _record("mr-delete", "BREAK", "DELETE lacks snapshot")
    hist = r._facts[("agent-a", "user/preference/theme")]
    if len(hist) != 2:
        return _record("mr-delete", "BREAK",
                       "old record was removed, not tombstoned")
    if hist[0]["fact_id"] != latest["fact_id"]:
        return _record("mr-delete", "BREAK", "old record mutated")
    _record("mr-delete", "HELD", "DELETE tombstones; history preserved")


def p_recall_tombstoned():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    dele = _candidate(r, owner_seed, op="delete",
                      supersedes=latest["fact_id"], written_at=1002)
    hist = [latest]
    r.reconcile(dele, hist, {}, 1002)
    _expect_code("mr-recall-tombstoned",
                 lambda: r.recall({"namespace": "agent-a",
                                   "key": "user/preference/theme"},
                                  "agent-a", 1003),
                 mr.RC_INVALID)


def p_recall_unscoped():
    mr = _mod()
    r, _, _ = _setup()
    for bad in (None, {}, {"namespace": "agent-a"}):
        _expect_code("mr-recall-unscoped-%r" % (bad,),
                     lambda b=bad: r.recall(b, "agent-a", 1000),
                     mr.RC_SCOPE_MISSING)


def p_cross_ns_no_grant():
    from gov import ed25519
    mr = _mod()
    r, owner_seed, _ = _setup()
    b_seed = _seed("owner-b")
    r.declare_namespace("agent-b", ed25519.publickey(b_seed).hex())
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    _expect_code("mr-cross-ns-no-grant",
                 lambda: r.recall({"namespace": "agent-a",
                                   "key": "user/preference/theme"},
                                  "agent-b", 1001),
                 mr.RC_UNAUTH_NS)


def p_grant_flow():
    from gov import ed25519
    mr = _mod()
    r, owner_seed, _ = _setup()
    b_seed = _seed("owner-b")
    r.declare_namespace("agent-b", ed25519.publickey(b_seed).hex())
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    grant = r.grant_sharing("agent-a", "agent-b", 900, 2000, owner_seed)
    # F376 (wave-300): cross-namespace recall is bearer-grant -- the
    # caller presents the signed grant; a bare namespace string never
    # authorizes.
    rec = r.recall({"namespace": "agent-a",
                    "key": "user/preference/theme"}, "agent-b", 1001,
                   grant=grant)
    if rec["state"] != "active":
        return _record("mr-grant-flow", "BREAK", "granted recall failed")
    # presenting the grant after its window still refuses
    _expect_code("mr-grant-expired",
                 lambda: r.recall({"namespace": "agent-a",
                                   "key": "user/preference/theme"},
                                  "agent-b", 2001, grant=grant),
                 mr.RC_UNAUTH_NS)
    # presenting a revoked grant still refuses
    r.revoke_grant(grant["grant_id"], owner_seed)
    _expect_code("mr-grant-revoked",
                 lambda: r.recall({"namespace": "agent-a",
                                   "key": "user/preference/theme"},
                                  "agent-b", 1500, grant=grant),
                 mr.RC_UNAUTH_NS)
    # no grant presented at all still refuses (F376 regression pin)
    _expect_code("mr-grant-absent",
                 lambda: r.recall({"namespace": "agent-a",
                                   "key": "user/preference/theme"},
                                  "agent-b", 1500),
                 mr.RC_UNAUTH_NS)
    # forged grant (wrong owner key) still refuses
    forged = dict(grant)
    forged["signature"] = "00" * 64
    _expect_code("mr-grant-forged",
                 lambda: r.recall({"namespace": "agent-a",
                                   "key": "user/preference/theme"},
                                  "agent-b", 1500, grant=forged),
                 mr.RC_UNAUTH_NS)
    _record("mr-grant-flow", "HELD",
            "grant permits recall; expiry and revocation refuse")


def p_forged_candidate():
    mr = _mod()
    r, owner_seed, _ = _setup()
    bad = _candidate(r, _seed("attacker"), written_at=1000)
    _expect_code("mr-forged-candidate",
                 lambda: r.reconcile(bad, [], {}, 1000),
                 mr.RC_UNAUTH_NS)


def p_forged_decision():
    mr = _mod()
    r, owner_seed, _ = _setup()
    dec = r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    tampered = dict(dec)
    tampered["decision"] = mr.RC_UPDATE
    _expect_code("mr-forged-decision",
                 lambda: r.verify_decision(tampered), mr.RC_INVALID)
    mangled = dict(dec)
    mangled["signature"] = "00" * 64
    _expect_code("mr-mangled-decision",
                 lambda: r.verify_decision(mangled), mr.RC_INVALID)


def p_rate_bound():
    mr = _mod()
    r = mr.MemoryReconciler(_seed("reconciler"), "recon-1",
                            max_writes_per_principal=2,
                            write_window_seconds=60)
    from gov import ed25519
    owner_seed = _seed("owner-a")
    r.declare_namespace("agent-a", ed25519.publickey(owner_seed).hex())
    r.reconcile(_candidate(r, owner_seed, key="k/one"), [], {}, 1000)
    r.reconcile(_candidate(r, owner_seed, key="k/two"), [], {}, 1001)
    _expect_code("mr-rate-bound",
                 lambda: r.reconcile(_candidate(r, owner_seed, key="k/3"),
                                     [], {}, 1002),
                 mr.RC_INVALID)


def p_undeclared_ns():
    mr = _mod()
    r, owner_seed, _ = _setup()
    cand = _candidate(r, owner_seed, namespace="agent-ghost",
                      written_at=1000)
    _expect_code("mr-undeclared-ns",
                 lambda: r.reconcile(cand, [], {}, 1000),
                 mr.RC_UNAUTH_NS)


def p_delete_tombstoned():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed), [], {}, 1000)
    latest = r.recall({"namespace": "agent-a",
                       "key": "user/preference/theme"}, "agent-a", 1001)
    dele = _candidate(r, owner_seed, op="delete",
                      supersedes=latest["fact_id"], written_at=1002)
    dec = r.reconcile(dele, [latest], {}, 1002)
    tomb_hist = r._facts[("agent-a", "user/preference/theme")]
    again = _candidate(r, owner_seed, op="delete",
                       supersedes=dec["fact_id"], written_at=1003)
    _expect_code("mr-delete-tombstoned",
                 lambda: r.reconcile(again, tomb_hist, {}, 1003),
                 mr.RC_INVALID)


def p_expiry_declared():
    mr = _mod()
    r, owner_seed, _ = _setup()
    r.reconcile(_candidate(r, owner_seed, expires_at=999999), [], {},
                1000)
    rec = r.recall({"namespace": "agent-a",
                    "key": "user/preference/theme"}, "agent-a", 1001)
    if rec["expires_at"] != 999999:
        return _record("mr-expiry", "BREAK", "retention not declared")
    _record("mr-expiry", "HELD", "retention declared at write time")


def p_ed25519_contract():
    from gov import ed25519
    seed = _seed("contract")
    pub = ed25519.publickey(seed)
    msg = b"contract-pin"
    sig = ed25519.sign(seed, msg)
    if ed25519.verify(pub, msg, sig) is not True:
        return _record("mr-ed25519-contract", "BREAK",
                       "good signature did not return True")
    bad = bytearray(sig)
    bad[0] ^= 1
    if ed25519.verify(pub, msg, bytes(bad)) is not False:
        return _record("mr-ed25519-contract", "BREAK",
                       "forged signature did not return False")
    _record("mr-ed25519-contract", "HELD",
            "ed25519.verify contract pinned (True/False)")


def _green_check(path, name, tolerate=()):
    if SKIP_GREEN:
        _record("green-%s" % name, "HELD", "skipped via GOV_SKIP_GREEN=1")
        return
    tmp = tempfile.mkdtemp(prefix="g298-green-")
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
        ("mr-import", p_import),
        ("mr-add", p_add),
        ("mr-noop", p_noop),
        ("mr-update-corroborated", p_update_corborated),
        ("mr-poison-refused", p_update_poison_refused),
        ("mr-archivist-override", p_update_archivist_override),
        ("mr-update-no-snapshot", p_update_no_supersedes),
        ("mr-add-conflict", p_add_conflict),
        ("mr-delete", p_delete_tombstones),
        ("mr-recall-tombstoned", p_recall_tombstoned),
        ("mr-recall-unscoped", p_recall_unscoped),
        ("mr-cross-ns-no-grant", p_cross_ns_no_grant),
        ("mr-grant-flow", p_grant_flow),
        ("mr-forged-candidate", p_forged_candidate),
        ("mr-forged-decision", p_forged_decision),
        ("mr-rate-bound", p_rate_bound),
        ("mr-undeclared-ns", p_undeclared_ns),
        ("mr-delete-tombstoned", p_delete_tombstoned),
        ("mr-expiry", p_expiry_declared),
        ("mr-ed25519-contract", p_ed25519_contract),
    ]:
        _safe(pid, fn)
    _green_check(os.path.join(REPO, "evals", "w297_supervision_probes.py"),
                 "w297-supervision", tolerate=("pin-taxonomy",))
    _green_check(os.path.join(REPO, "evals", "w296_decision_trace_probes.py"),
                 "w296-decision-trace", tolerate=("pin-taxonomy",))
    n_break = sum(1 for _, v, _ in _results if v == "BREAK")
    n_held = sum(1 for _, v, _ in _results if v == "HELD")
    n_err = sum(1 for _, v, _ in _results if v == "ERROR")
    print("w298_memory_reconcile: %d BREAK / %d HELD / %d ERROR"
          % (n_break, n_held, n_err))
    _coh_ok, _coh_diags = probe_lines.check_coherence(
        _results, n_break, n_held, n_err)
    if not _coh_ok:
        print("coherence-WARNING: %s" % "; ".join(_coh_diags))
    probe_lines.emit(_results)
    sys.exit(1 if (n_break or n_err) else 0)


if __name__ == "__main__":
    main()
