"""Wave-301 independent red-team battery: wave-300 composition seams under attack.

Targets:
  1. gov/memory_composed.py -- adapter confusion (store-shaped records
     where reconcile-shaped are expected), generation-suffix key games
     (adversary pre-seeding "<key>-g<N>"), grade-narrowing bypasses,
     bi-temporal mapping lies (forged written_at), signature-domain
     confusion (observer key presented as owner key), bind_store
     overwrite asymmetry.
  2. gov/coordination_lease.py delegation_binding -- multi-hop
     revocation visibility (F379), renew-then-revoke races, unbound
     grant + stray delegation context, expired-receipt mapping,
     binding declared on an already-revoked receipt.
  3. gov/delegation_approval.py -- digest-binding substitution (chain
     swap, right swap), envelope tampering, requester/tip mismatch,
     chain expiry vs revocation ordering, unheld rights, backdated
     verification instants, tampered middle links, non-holder issue,
     malformed packages, empty trust roots, revoked-chain-no-revoker
     (documented residual).
  4. F377/F378 expected-open controls: reproduced on pristine base via
     the wave-300 battery's own probe classes; their BREAKs are
     reported separately from the new F379 BREAKs.

Base: wave-300 merge 94bc43deb58ba78163f3ee61a59c2240cdd008f3
(verified via git rev-parse HEAD after clone; git ls-remote agreed).

Pin 1812 at lane time (this lane mints no decision codes -- attack
only; gov/ stays byte-identical). Next free F380 at lane time (F379
filed by this lane).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g301-rt && TMPDIR=/var/tmp/g301-rt \\
    ~/workspace/.gov-venv/bin/python evals/w301_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g301-rtb \\
    ~/workspace/.gov-venv/bin/python evals/w301_redteam_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import copy
import hashlib
import json
import re
import subprocess
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import coordination_lease as cl
from gov import delegation as dg
from gov import delegation_approval as da
from gov import delegation_revocation as rev
from gov import ed25519 as _ed25519
from gov import memory_composed as mc
from gov import memory_reconcile as mr
from gov import memory_store as ms

TAXONOMY_PIN = 2044 # Wave-301 merge pin 1812 (was 1802 at wave-300); this lane mints no codes.; Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 4: pin 1820 -> 1822 (+2 workflow-saga-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary)



_results = []


def _record(name, status, detail=""):
    _results.append((name, status, detail))
    return status


def _expect_coded(name, fn, codes):
    """fn must raise a coded error whose .code is in codes. Anything
    else (no raise, uncoded raise, wrong code) is a BREAK."""
    try:
        fn()
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "code", None)
        if code in codes:
            return _record(name, "HELD", "coded %s" % (code,))
        return _record(name, "BREAK",
                       "wrong escape: %s(code=%r), want one of %s"
                       % (type(e).__name__, code, sorted(codes)))
    return _record(name, "BREAK", "no refusal: fn returned")


def _expect_held(name, cond, detail=""):
    if cond:
        return _record(name, "HELD", detail)
    return _record(name, "BREAK", detail or "condition false")


def _seed(tag):
    return hashlib.sha256(("w301-redteam-%s" % tag).encode()).digest()


def _pub(seed):
    return _ed25519.publickey(seed).hex()


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()


def _literals():
    with open(os.path.join(REPO, "gov", "decision_codes.py"),
              encoding="utf-8") as fh:
        src = fh.read()
    return re.findall(r'"code":\s*\'([a-z][a-z0-9-_.]*)\'', src)


class BaseStateTest(unittest.TestCase):
    def test_footer_state(self):
        with open(os.path.join(REPO, "evals", "FINDINGS.md"),
                  encoding="utf-8") as fh:
            text = fh.read()
        m_open = re.findall(r"Open findings: ([A-Za-z0-9, ]*)", text)
        m_next = re.findall(r"Next free finding: \*\*(F\d+)\*\*", text)
        # Wave-324 merge: F408 CLOSED; open none; next F409.
        ok = (m_open and m_open[-1].strip().lower() == "none"
              and m_next and m_next[-1] == "F412")
        self.assertTrue(_expect_held(
            "footer-state", ok,
            "want open none / next free F409") == "HELD")

    def test_pin(self):
        lits = _literals()
        ok = (len(lits) == TAXONOMY_PIN and len(set(lits)) == TAXONOMY_PIN
              and lits == sorted(lits))
        self.assertTrue(_expect_held(
            "taxonomy-pin",
            ok and TAXONOMY_PIN == 2044,


            "%d literals / %d unique / sorted=%s"
            % (len(lits), len(set(lits)), lits == sorted(lits))) == "HELD")


# ---------------------------------------------------------------------------
# Closure controls: F377 / F378 (wave-301 lanes 1-2 closures).
# Verified on the merged tree via the wave-300 battery's own probe
# classes. Their BREAKs are BREAK-iff-vulnerable: they BREAK on the
# pristine base and flip HELD once the closures land.
# ---------------------------------------------------------------------------

class F377F378ControlTest(unittest.TestCase):
    def test_F377_F378_closed(self):
        import evals.w300_redteam_probes as w300
        before = len(w300._results)
        suite = unittest.TestSuite()
        loader = unittest.TestLoader()
        suite.addTests(loader.loadTestsFromTestCase(
            w300.F377DIDTrustRootTest))
        suite.addTests(loader.loadTestsFromTestCase(
            w300.F378TicketRevocationTest))
        runner = unittest.TextTestRunner(verbosity=0, stream=open(
            os.devnull, "w"))
        result = runner.run(suite)
        new = w300._results[before:]
        breaks = sorted(n for n, s, _ in new if s == "BREAK")
        # Wave-301 merge re-pin: lanes 1-2 CLOSED F377/F378, so the
        # BREAK-iff-vulnerable probes flip HELD; expect 0 BREAKs.
        want = []
        ok = (result.wasSuccessful() and breaks == want)
        # Recorded HELD in THIS battery: the controls confirm the
        # closures (0 BREAKs; the F377/F378 probes flipped HELD).
        self.assertTrue(_expect_held(
            "F377-F378-closed",
            ok,
            "w300 controls: %d BREAKs %s" % (len(breaks), breaks)) == "HELD")


# ---------------------------------------------------------------------------
# Target 1: memory_composed seams.
# ---------------------------------------------------------------------------

def _mc_provenance(**kw):
    base = {"source_principal": "agent-a", "reliability": "C3",
            "corroborations": 0, "ingested_at": 1000}
    base.update(kw)
    return base


def _mc_candidate(owner_seed, key="user-theme", value="dark", op="add",
                  supersedes=None, provenance=None, namespace="agent-a",
                  written_at=1000, expires_at=None, sign_seed=None):
    vd = hashlib.sha256(value.encode()).hexdigest()
    cand = {"schema": "memory-record/v1", "namespace": namespace,
            "key": key, "value_digest": vd, "written_at": written_at,
            "supersedes": supersedes,
            "provenance": provenance or _mc_provenance(),
            "expires_at": expires_at, "op": op}
    body = {k: cand[k] for k in
            ("schema", "namespace", "key", "value_digest", "written_at",
             "supersedes", "provenance", "expires_at", "op")}
    cand["signature"] = _ed25519.sign(sign_seed or owner_seed,
                                      _canon(body)).hex()
    return cand


def _mc_setup():
    r = mr.MemoryReconciler(_seed("mc-reconciler"), "recon-1",
                            max_writes_per_principal=10000,
                            write_window_seconds=3600)
    owner_seed = _seed("mc-owner-a")
    r.declare_namespace("agent-a", _pub(owner_seed))
    store = ms.MemoryStore()
    comp = mc.MemoryComposer(r, {"agent-a": owner_seed})
    comp.bind_store("agent-a", store)
    return r, comp, owner_seed, store


def _mc_episode(store, seed, principal, at):
    pub = _pub(seed)
    body = {"agent_id": principal,
            "content_digest": hashlib.sha256(b"x").hexdigest(),
            "source_principal": principal, "source_pubkey": pub,
            "recorded_at": at}
    sig = _ed25519.sign(seed, _canon(body)).hex()
    return store.record_episode(principal, body["content_digest"],
                                principal, pub, sig, at)


def _mc_direct_fact(store, seed, principal, store_key, value, valid_at,
                    recorded_at):
    eid = _mc_episode(store, seed, principal, recorded_at)
    pub = _pub(seed)
    vd = hashlib.sha256(value.encode()).hexdigest()
    body = {"statement_key": store_key, "statement_digest": vd,
            "source_episode_ids": [eid], "source_principal": principal,
            "source_pubkey": pub, "valid_at": valid_at,
            "retain_until": None, "reliability": "C", "credibility": 3,
            "created_at": recorded_at}
    sig = _ed25519.sign(seed, _canon(body)).hex()
    return store.record_fact(store_key, vd, [eid], principal, pub, sig,
                             valid_at, recorded_at,
                             reliability="C", credibility=3)


class MemoryComposedSeamTest(unittest.TestCase):
    """Target 1: the six resolved hazards plus the discovered key-grammar
    seam, attacked at the adapter boundary."""

    def test_adapter_confusion_store_shaped_candidate(self):
        # A store-shaped record offered where a reconcile candidate is
        # expected must refuse coded -- never silently accepted.
        _, comp, _, store = _mc_setup()
        self.assertTrue(_expect_coded(
            "mc-store-shaped-candidate",
            lambda: comp.composed_write(
                "agent-a", {"fact_id": "abc", "statement_key": "k"},
                store, {}, 1000),
            {"memory-reconcile-invalid"}) == "HELD")

    def test_grade_narrowing_holds(self):
        # The composed path accepts only the reconciler 8-token set;
        # wider grades refuse BEFORE the store split (fail-closed
        # narrowing, Decision 4).
        for grade in ("E5", "C10", "A9"):
            _, comp, owner_seed, store = _mc_setup()
            self.assertTrue(_expect_coded(
                "mc-grade-%s-refused" % grade,
                lambda: comp.composed_write(
                    "agent-a",
                    _mc_candidate(owner_seed,
                                  provenance=_mc_provenance(
                                      reliability=grade)),
                    store, {}, 1000),
                {"memory-reconcile-invalid"}) == "HELD")

    def test_observer_key_not_owner_key(self):
        # Signature-domain confusion: a candidate signed by an observer
        # key (not the namespace owner's declared key) must refuse --
        # the reconciler authenticates writers against the declared
        # owner key (Decision 6).
        _, comp, owner_seed, store = _mc_setup()
        self.assertTrue(_expect_coded(
            "mc-observer-signed-refused",
            lambda: comp.composed_write(
                "agent-a",
                _mc_candidate(owner_seed,
                              sign_seed=_seed("mc-observer-evil")),
                store, {}, 1000),
            {"memory-reconcile-unauthorized-namespace"}) == "HELD")

    def test_generation_suffix_preseed_absorbed(self):
        # Adversary pre-seeds "<key>-g1" directly in the store, then
        # the victim retracts and re-adds (gen 1 lands on the
        # pre-seeded key). The composer's record_fact SUPERSEDES the
        # attacker's open record; recall returns the victim's value
        # and no divergence alarm fires. HELD: the pre-seed is
        # neutralized, not exploitable -- but the fork is silently
        # absorbed (documented residual: the composer is the single
        # writer by threat model; second writers are out of scope).
        r, comp, owner_seed, store = _mc_setup()
        evil = _seed("mc-evil")
        comp.composed_write(
            "agent-a", _mc_candidate(owner_seed, key="victim-key",
                                    value="v1"), store, {}, 1000)
        _mc_direct_fact(store, evil, "evil", "victim-key-g1",
                        "evilval", 1000, 1000)
        d1 = r._facts[("agent-a", "victim-key")][-1]["fact_id"]
        comp.composed_write(
            "agent-a",
            _mc_candidate(owner_seed, key="victim-key", value="v1",
                          op="delete", supersedes=d1, written_at=1001),
            store, {}, 1001)
        out = comp.composed_write(
            "agent-a",
            _mc_candidate(owner_seed, key="victim-key", value="v2",
                          written_at=1002), store, {}, 1002)
        view = comp.composed_recall(
            "agent-a", {"namespace": "agent-a", "key": "victim-key"},
            "agent-a", 1003)
        ok = (out["generation"] == 1 and view["value_digest"]
              == hashlib.sha256(b"v2").hexdigest())
        self.assertTrue(_expect_held(
            "mc-gen-suffix-preseed-absorbed", ok,
            "pre-seeded <key>-g1 superseded; victim value recalled, "
            "no silent corruption") == "HELD")

    def test_posthoc_hijack_detected(self):
        # Adversary writes under the live generation key AFTER the
        # victim's gen-1 write: the store supersedes the victim's
        # record, but composed_recall's digest check refuses
        # memory-composed-divergent -- the fork IS caught here.
        r, comp, owner_seed, store = _mc_setup()
        evil = _seed("mc-evil")
        comp.composed_write(
            "agent-a", _mc_candidate(owner_seed, key="k2", value="v1"),
            store, {}, 1000)
        d1 = r._facts[("agent-a", "k2")][-1]["fact_id"]
        comp.composed_write(
            "agent-a",
            _mc_candidate(owner_seed, key="k2", value="v1", op="delete",
                          supersedes=d1, written_at=1001), store, {}, 1001)
        comp.composed_write(
            "agent-a",
            _mc_candidate(owner_seed, key="k2", value="v2",
                          written_at=1002), store, {}, 1002)
        _mc_direct_fact(store, evil, "evil", "k2-g1", "hijack", 900, 1003)
        self.assertTrue(_expect_coded(
            "mc-posthoc-hijack-divergent",
            lambda: comp.composed_recall(
                "agent-a", {"namespace": "agent-a", "key": "k2"},
                "agent-a", 1004),
            {"memory-composed-divergent"}) == "HELD")

    def test_future_written_at_recall_refuses(self):
        # Bi-temporal mapping lie: a future written_at becomes a
        # future valid_at; recall before validity refuses
        # memory-store-expired (Decision 5 -- the store's strictness
        # is a feature, fail-closed).
        _, comp, owner_seed, store = _mc_setup()
        comp.composed_write(
            "agent-a",
            _mc_candidate(owner_seed, key="fk", value="v1",
                          written_at=9999), store, {}, 1000)
        self.assertTrue(_expect_coded(
            "mc-future-written-at-refused",
            lambda: comp.composed_recall(
                "agent-a", {"namespace": "agent-a", "key": "fk"},
                "agent-a", 1001),
            {"memory-store-expired"}) == "HELD")

    def test_bind_store_overwrite_fails_closed(self):
        # Asymmetry: _store_for refuses a different store object
        # (fork attempt), but bind_store overwrites unconditionally.
        # The overwrite does NOT corrupt: the ledger's store_keys no
        # longer exist in the new store, so recall refuses coded
        # (fail-closed, not silent).
        _, comp, owner_seed, store = _mc_setup()
        comp.composed_write(
            "agent-a", _mc_candidate(owner_seed, key="k", value="v"),
            store, {}, 1000)
        comp.bind_store("agent-a", ms.MemoryStore())
        self.assertTrue(_expect_coded(
            "mc-bind-store-overwrite-fails-closed",
            lambda: comp.composed_recall(
                "agent-a", {"namespace": "agent-a", "key": "k"},
                "agent-a", 1001),
            {"memory-store-invalid"}) == "HELD")


# ---------------------------------------------------------------------------
# Target 2: revocation<->lease fencing.
# ---------------------------------------------------------------------------

_AT = 1_700_000_000


def _lease_native(seed, delegator_id, delegatee_id, delegatee_pub,
                  parent=None):
    did = delegatee_id
    return dg.issue(seed, delegator_id, did, delegatee_pub,
                    ["lease.acquire"], parent=parent,
                    constraints={"expires_at": _AT + 3600, "max_depth": 4,
                                 "allowed_targets": [did]},
                    issued_at=_AT)


def _lease_bound_mgr(scope="u-scope", holder="holder"):
    sa, sb = _seed("lease-a"), _seed("lease-b")
    root = _lease_native(sa, "authority", holder, _pub(sb))
    rvk = rev.DelegationRevoker(sa, "authority")
    mgr = cl.LeaseManager()
    lease = mgr.acquire(
        scope, 3600, holder, authority_seed=sa, issued_at=_AT,
        delegation_binding={"receipt_id": root["receipt_id"],
                            "revocation_list_digest": rvk.list_digest()})
    ctx = {"revoker": rvk, "chain": [root], "trust_roots": [_pub(sa)]}
    return mgr, lease, rvk, root, ctx


class RevokeLeaseSeamTest(unittest.TestCase):
    """Target 2: the delegation_binding seam in check_write."""

    def test_F379_multihop_intermediate_revocation_invisible(self):
        # F379 (MEDIUM, CLOSED wave-302 lane 1): for a multi-hop chain
        # bound at the leaf, every delegator's revocation list is now
        # consulted. When the leaf's own delegator (an intermediate
        # hop) revokes the bound receipt, the write must refuse
        # coord-lease-fencing -- both under the legacy single-revoker
        # shape (fail closed: the intermediate hop's state cannot be
        # shown) and under the new per-delegator revokers mapping.
        sa, sb, sc = _seed("f379-a"), _seed("f379-b"), _seed("f379-c")
        root = _lease_native(sa, "authority-a", "holder-b", _pub(sb))
        # Re-delegate holder-b -> holder-c (multi-hop chain).
        child = dg.issue(sb, "holder-b", "holder-c", _pub(sc),
                         ["lease.acquire"], parent=root,
                         constraints={"expires_at": _AT + 3600,
                                      "max_depth": 4,
                                      "allowed_targets": ["holder-c"]},
                         issued_at=_AT)
        rev_a = rev.DelegationRevoker(sa, "authority-a")
        rev_b = rev.DelegationRevoker(sb, "holder-b")
        mgr = cl.LeaseManager()
        lease = mgr.acquire(
            "f379-scope", 3600, "holder-c", authority_seed=sa,
            issued_at=_AT,
            delegation_binding={
                "receipt_id": child["receipt_id"],
                "revocation_list_digest": rev_a.list_digest()})
        # The leaf's delegator revokes the bound receipt.
        rev_b.revoke(child["receipt_id"], _AT + 5)
        # Legacy shape: only the root's revoker presented -- the
        # intermediate hop's revocation state is unshowable, so the
        # write fails closed instead of passing on the root's clean
        # list as wave-300 did.
        legacy_ctx = {"revoker": rev_a, "chain": [root, child],
                      "trust_roots": [_pub(sa)]}
        try:
            mgr.check_write("f379-scope", lease["fencing_token"],
                            "holder-c", checked_at=_AT + 10,
                            delegation_context=legacy_ctx)
            legacy_code = "NO-REFUSAL"
        except Exception as e:  # noqa: BLE001
            legacy_code = getattr(e, "code", None)
        # New shape: per-delegator revokers -- B's revocation is
        # enforced.
        map_ctx = {"revokers": {"authority-a": rev_a,
                               "holder-b": rev_b},
                   "chain": [root, child], "trust_roots": [_pub(sa)]}
        try:
            mgr.check_write("f379-scope", lease["fencing_token"],
                            "holder-c", checked_at=_AT + 10,
                            delegation_context=map_ctx)
            map_code = "NO-REFUSAL"
        except Exception as e:  # noqa: BLE001
            map_code = getattr(e, "code", None)
        self.assertTrue(_expect_held(
            "F379-intermediate-revocation-fenced",
            legacy_code == "coord-lease-fencing"
            and map_code == "coord-lease-fencing",
            "legacy=%r mapping=%r; want coord-lease-fencing both"
            % (legacy_code, map_code)) == "HELD")

    def test_F379_correct_revoker_structurally_refused(self):
        # F379 (MEDIUM, CLOSED wave-302 lane 1): the leaf delegator's
        # OWN revoker is now a first-class citizen via the
        # per-delegator revokers mapping -- presenting it enforces
        # its revocation (fencing), instead of being structurally
        # refused as invalid for not being the root's.
        sa, sb, sc = _seed("f379b-a"), _seed("f379b-b"), _seed("f379b-c")
        root = _lease_native(sa, "authority-a", "holder-b", _pub(sb))
        child = dg.issue(sb, "holder-b", "holder-c", _pub(sc),
                         ["lease.acquire"], parent=root,
                         constraints={"expires_at": _AT + 3600,
                                      "max_depth": 4,
                                      "allowed_targets": ["holder-c"]},
                         issued_at=_AT)
        rev_a = rev.DelegationRevoker(sa, "authority-a")
        rev_b = rev.DelegationRevoker(sb, "holder-b")
        mgr = cl.LeaseManager()
        lease = mgr.acquire(
            "f379b-scope", 3600, "holder-c", authority_seed=sa,
            issued_at=_AT,
            delegation_binding={
                "receipt_id": child["receipt_id"],
                "revocation_list_digest": rev_a.list_digest()})
        rev_b.revoke(child["receipt_id"], _AT + 5)
        ctx = {"revokers": {"authority-a": rev_a, "holder-b": rev_b},
               "chain": [root, child], "trust_roots": [_pub(sa)]}
        try:
            mgr.check_write("f379b-scope", lease["fencing_token"],
                            "holder-c", checked_at=_AT + 10,
                            delegation_context=ctx)
            code = "NO-REFUSAL"
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
        # The genuine revocation is enforced (fencing), not refused
        # as structurally invalid.
        self.assertTrue(_expect_held(
            "F379-correct-revoker-enforced", code == "coord-lease-fencing",
            "leaf delegator's revoker gave %r; want "
            "coord-lease-fencing" % (code,)) == "HELD")

    def test_renew_then_revoke_fences(self):
        # Renewal preserves the binding; a later revocation still
        # fences the write (renew is an authority-seed action and does
        # not itself consult revocation -- the write does).
        mgr, lease, rvk, root, ctx = _lease_bound_mgr(scope="r1")
        lease2 = mgr.renew("r1", lease["fencing_token"], "holder", 3600,
                           authority_seed=_seed("lease-a"),
                           checked_at=_AT + 10)
        self.assertTrue(_expect_held(
            "lease-renew-live-write",
            mgr.check_write("r1", lease2["fencing_token"], "holder",
                            checked_at=_AT + 20,
                            delegation_context=ctx) is True) == "HELD")
        rvk.revoke(root["receipt_id"], _AT + 30)
        self.assertTrue(_expect_coded(
            "lease-renew-then-revoke-fences",
            lambda: mgr.check_write(
                "r1", lease2["fencing_token"], "holder",
                checked_at=_AT + 40, delegation_context=ctx),
            {"coord-lease-fencing"}) == "HELD")

    def test_unbound_stray_context_ignored(self):
        # Grants without a binding behave exactly as before: a stray
        # delegation_context is ignored (documented).
        sa = _seed("lease-a")
        mgr = cl.LeaseManager()
        lease = mgr.acquire("r2", 3600, "holder-x", authority_seed=sa,
                            issued_at=_AT)
        _, _, rvk, root, _ = _lease_bound_mgr(scope="r2b")
        stray = {"revoker": rvk, "chain": [root],
                 "trust_roots": [_pub(_seed("lease-a"))]}
        self.assertTrue(_expect_held(
            "lease-unbound-stray-context-ignored",
            mgr.check_write("r2", lease["fencing_token"], "holder-x",
                            checked_at=_AT + 10,
                            delegation_context=stray) is True) == "HELD")

    def test_expired_receipt_maps_expired(self):
        # delegation-expired maps onto coord-lease-expired (the
        # documented code mapping).
        sa, sb = _seed("lease-ea"), _seed("lease-eb")
        root = dg.issue(sa, "authority", "holder", _pub(sb),
                        ["lease.acquire"],
                        constraints={"expires_at": _AT + 100,
                                     "max_depth": 4,
                                     "allowed_targets": ["holder"]},
                        issued_at=_AT)
        rvk = rev.DelegationRevoker(sa, "authority")
        mgr = cl.LeaseManager()
        lease = mgr.acquire(
            "r3", 36000, "holder", authority_seed=sa, issued_at=_AT,
            delegation_binding={
                "receipt_id": root["receipt_id"],
                "revocation_list_digest": rvk.list_digest()})
        ctx = {"revoker": rvk, "chain": [root], "trust_roots": [_pub(sa)]}
        self.assertTrue(_expect_coded(
            "lease-expired-receipt-maps-expired",
            lambda: mgr.check_write(
                "r3", lease["fencing_token"], "holder",
                checked_at=_AT + 5000, delegation_context=ctx),
            {"coord-lease-expired"}) == "HELD")

    def test_bind_on_revoked_first_write_fences(self):
        # A binding declared on an already-revoked receipt: acquire
        # succeeds (the binding is declared, not verified), but the
        # first bound write fences fail-closed.
        mgr, lease, rvk, root, ctx = _lease_bound_mgr(scope="r4")
        rvk.revoke(root["receipt_id"], _AT + 5)
        self.assertTrue(_expect_coded(
            "lease-bind-on-revoked-fences",
            lambda: mgr.check_write(
                "r4", lease["fencing_token"], "holder",
                checked_at=_AT + 10, delegation_context=ctx),
            {"coord-lease-fencing"}) == "HELD")


# ---------------------------------------------------------------------------
# Target 3: delegation_approval seams.
# ---------------------------------------------------------------------------

def _da_seed(tag):
    return hashlib.sha256(("w301-da-%s" % tag).encode()).digest()


_DA_AT = 1_700_000_000
_DA_SA = _da_seed("a")
_DA_SB = _da_seed("b")
_DA_SC = _da_seed("c")
_DA_PA = _pub(_DA_SA)


def _da_root(tag, delegatee_seed, rights=("tool.invoke",), exp=None):
    exp = _DA_AT + 3600 if exp is None else exp
    did = "agent-" + tag
    return dg.issue(_DA_SA, "agent-a", did, _pub(delegatee_seed),
                    list(rights),
                    constraints={"expires_at": exp, "max_depth": 4,
                                 "allowed_targets": [did]},
                    issued_at=_DA_AT)


def _da_pkg(chain, right="tool.invoke", rid="agent-b", seed=None,
            ttl=3600, iat=_DA_AT):
    seed = _DA_SB if seed is None else seed
    return da.issue_delegated_request(
        chain=chain, delegation_right=right,
        action={"tool": "shell", "args": {"cmd": "ls"}},
        requester_agent_id=rid, requester_principal="principal-" + rid,
        requester_pubkey_hex=_pub(seed), requester_seed=seed,
        approver_schema=[], ttl_seconds=ttl, issued_at=iat)


def _da_verify(package, **kw):
    kw.setdefault("at", _DA_AT)
    kw.setdefault("trust_roots", [_DA_PA])
    return da.verify_delegated_request(package, **kw)


class DelegationApprovalSeamTest(unittest.TestCase):
    """Target 3: digest bindings, ordering, and package shapes."""

    def test_chain_swap_refused(self):
        # A different valid chain under the same envelope: the bound
        # chain digest must mismatch.
        r1 = _da_root("b", _DA_SB)
        r2 = _da_root("b2", _da_seed("b2"))
        assert r1["receipt_id"] != r2["receipt_id"]
        p = _da_pkg([r1])
        self.assertTrue(_expect_coded(
            "da-chain-swap-refused",
            lambda: _da_verify({"envelope": p["envelope"],
                                "chain": [dict(r2)],
                                "delegation_right": "tool.invoke"}),
            {"delegation-approval-chain-mismatch"}) == "HELD")

    def test_right_swap_refused(self):
        p = _da_pkg([_da_root("b", _DA_SB)])
        self.assertTrue(_expect_coded(
            "da-right-swap-refused",
            lambda: _da_verify({"envelope": p["envelope"],
                                "chain": p["chain"],
                                "delegation_right": "lease.acquire"}),
            {"delegation-approval-right-mismatch"}) == "HELD")

    def test_envelope_tamper_refused(self):
        p = _da_pkg([_da_root("b", _DA_SB)])
        env = copy.deepcopy(p["envelope"])
        env["request"]["context_digests"][
            "delegation_chain_digest"] = "0" * 64
        self.assertTrue(_expect_coded(
            "da-envelope-tamper-refused",
            lambda: _da_verify({"envelope": env, "chain": p["chain"],
                                "delegation_right": "tool.invoke"}),
            {"approval-request-forgery"}) == "HELD")

    def test_requester_not_tip_refused(self):
        # Hand-built package: envelope signed by X, chain tipped by
        # someone else. The digest binding fires first; authorize
        # would independently refuse delegation-chain-broken.
        r = _da_root("b", _DA_SB)
        pe = _da_pkg([r], rid="agent-b", seed=_DA_SB)
        rx = _da_root("x", _da_seed("evil"))
        self.assertTrue(_expect_coded(
            "da-requester-not-tip-refused",
            lambda: _da_verify({"envelope": pe["envelope"],
                                "chain": [dict(rx)],
                                "delegation_right": "tool.invoke"}),
            {"delegation-approval-chain-mismatch"}) == "HELD")

    def test_expired_chain_refused(self):
        r = _da_root("b", _DA_SB, exp=_DA_AT + 100)
        p = _da_pkg([r], ttl=3600 * 10)
        self.assertTrue(_expect_coded(
            "da-expired-chain-refused",
            lambda: _da_verify(p, at=_DA_AT + 5000),
            {"delegation-expired"}) == "HELD")

    def test_revocation_beats_expiry(self):
        # Revoked AND expired chain with a revoker: revocation is
        # checked before authorize, so delegation-revoked wins.
        r = _da_root("b", _DA_SB, exp=_DA_AT + 100)
        p = _da_pkg([r], ttl=3600 * 10)
        rvk = rev.DelegationRevoker(_DA_SA, "agent-a")
        rvk.revoke(r["receipt_id"], _DA_AT + 50)
        self.assertTrue(_expect_coded(
            "da-revocation-beats-expiry",
            lambda: _da_verify(p, at=_DA_AT + 5000, revoker=rvk),
            {"delegation-revoked"}) == "HELD")

    def test_revoked_unexpired_refused(self):
        r = _da_root("b", _DA_SB)
        p = _da_pkg([r], ttl=3600 * 10)
        rvk = rev.DelegationRevoker(_DA_SA, "agent-a")
        rvk.revoke(r["receipt_id"], _DA_AT + 50)
        self.assertTrue(_expect_coded(
            "da-revoked-unexpired-refused",
            lambda: _da_verify(p, at=_DA_AT + 500, revoker=rvk),
            {"delegation-revoked"}) == "HELD")

    def test_unheld_right_refused(self):
        # issue() binds any RIGHTS member without verifying the
        # chain; verify's authorize refuses what the leaf lacks.
        r = _da_root("b", _DA_SB, rights=("tool.invoke",))
        p = _da_pkg([r], right="lease.acquire")
        self.assertTrue(_expect_coded(
            "da-unheld-right-refused",
            lambda: _da_verify(p),
            {"delegation-invalid"}) == "HELD")

    def test_backdated_instant_refused(self):
        p = _da_pkg([_da_root("b", _DA_SB)])
        self.assertTrue(_expect_coded(
            "da-backdated-instant-refused",
            lambda: _da_verify(p, at=_DA_AT - 100),
            {"approval-request-invalid"}) == "HELD")

    def test_tampered_middle_link_refused(self):
        sc = _da_seed("c")
        r_ab = _da_root("b", _DA_SB)
        r_bc = dg.issue(_DA_SB, "agent-b", "agent-c", _pub(sc),
                        ["tool.invoke"], parent=r_ab,
                        constraints={"expires_at": _DA_AT + 3600,
                                     "max_depth": 4,
                                     "allowed_targets": ["agent-c"]},
                        issued_at=_DA_AT)
        pc = _da_pkg([r_ab, r_bc], rid="agent-c", seed=sc)
        tam = copy.deepcopy(pc)
        tam["chain"][1]["rights"] = ["tool.invoke", "lease.acquire"]
        self.assertTrue(_expect_coded(
            "da-tampered-middle-link-refused",
            lambda: _da_verify(tam),
            {"delegation-chain-broken"}) == "HELD")

    def test_non_holder_issue_refused(self):
        r = _da_root("b", _DA_SB)
        evil = _da_seed("evil")
        self.assertTrue(_expect_coded(
            "da-non-holder-issue-refused",
            lambda: _da_pkg([r], rid="agent-evil", seed=evil),
            {"delegation-invalid"}) == "HELD")

    def test_tuple_chain_refused(self):
        p = _da_pkg([_da_root("b", _DA_SB)])
        self.assertTrue(_expect_coded(
            "da-tuple-chain-refused",
            lambda: _da_verify({"envelope": p["envelope"],
                                "chain": tuple(p["chain"]),
                                "delegation_right": "tool.invoke"}),
            {"delegation-invalid"}) == "HELD")

    def test_extra_package_field_refused(self):
        p = _da_pkg([_da_root("b", _DA_SB)])
        bad = dict(p)
        bad["extra"] = 1
        self.assertTrue(_expect_coded(
            "da-extra-package-field-refused",
            lambda: _da_verify(bad),
            {"delegation-invalid"}) == "HELD")

    def test_empty_trust_roots_refused(self):
        p = _da_pkg([_da_root("b", _DA_SB)])
        self.assertTrue(_expect_coded(
            "da-empty-trust-roots-refused",
            lambda: _da_verify(p, trust_roots=[]),
            {"delegation-root-untrusted"}) == "HELD")

    def test_revoked_no_revoker_documented(self):
        # Documented residual (module docstring): a verifier that
        # never presents a revoker accepts revoked-but-unexpired
        # chains. HELD as documented -- revocation distribution is
        # deployment-owned; pass revoker when revocation matters.
        r = _da_root("b", _DA_SB)
        p = _da_pkg([r])
        rvk = rev.DelegationRevoker(_DA_SA, "agent-a")
        rvk.revoke(r["receipt_id"], _DA_AT + 10)
        ok = _da_verify(p, at=_DA_AT + 20) is not None
        self.assertTrue(_expect_held(
            "da-revoked-no-revoker-documented", ok,
            "verifier without revoker accepts revoked chain -- "
            "documented residual, pass revoker when it matters")
            == "HELD")


class RepinTest(unittest.TestCase):
    def test_pin_repin(self):
        lits = _literals()
        self.assertTrue(_expect_held(
            "repin-pin-1851",
            len(lits) == 2044 and len(set(lits)) == 2044


            and lits == sorted(lits),
            "1851 unique sorted literals") == "HELD")


def _green_check(battery, expect):
    if os.environ.get("GOV_SKIP_GREEN"):
        return ("HELD", "skipped (depth-1)")
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = "/var/tmp/g301-green-%s" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    path = os.path.join(REPO, "evals", battery)
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            env=env, timeout=600)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s" % (e,))
    if expect in (out.stdout + out.stderr):
        summary = (out.stdout.strip().splitlines() or ["no output"])[0]
        return ("HELD", summary)
    return ("BREAK", (out.stdout.strip().splitlines() or ["no output"])[0])


class GreenCheckTest(unittest.TestCase):
    def test_green_w300_redteam(self):
        # Wave-301 merge re-pin: F377/F378 CLOSED by lanes 1-2 (their
        # probes flip HELD, incl. lane 2's 4 new F378 probes); footers
        # re-pinned to the merged footer (open F379 / next F380).
        # Verified on the merged tree: 0 BREAK / 34 HELD / 0 ERROR.
        status, detail = _green_check("w300_redteam_probes.py",
                                      "0 BREAK / 34 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w300-redteam", status == "HELD", detail) == "HELD")

    def test_green_w300_memory_composed(self):
        status, detail = _green_check("w300_memory_composed_probes.py",
                                      "w300_memory_composed: "
                                      "0 BREAK / 30 HELD / 0 ERROR")
        self.assertTrue(_expect_held(
            "green-w300-memory-composed",
            status == "HELD", detail) == "HELD")

    def test_green_w300_delegation_approval(self):
        status, detail = _green_check("w300_delegation_approval_probes.py",
                                      "OK")
        self.assertTrue(_expect_held(
            "green-w300-delegation-approval",
            status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, F377F378ControlTest,
                MemoryComposedSeamTest, RevokeLeaseSeamTest,
                DelegationApprovalSeamTest, RepinTest, GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    n_break = sum(1 for _, s, _ in _results if s == "BREAK")
    n_held = sum(1 for _, s, _ in _results if s == "HELD")
    n_err = sum(1 for _, s, _ in _results if s == "ERROR")
    print("%d BREAK / %d HELD / %d ERROR" % (n_break, n_held, n_err))
    for name, status, detail in _results:
        if status != "HELD":
            print("  %s: %s %s" % (status, name, detail))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main())
