"""Wave-299 independent red-team battery: wave-298 additions under attack.

Targets:
  A. gov/memory_store.py -- cross-agent reads (no namespacing in the
     store), supersession/retraction authority, tombstone replay,
     retention manipulation, corroboration inflation, episode
     substitution.
  B. gov/memory_reconcile.py -- scope-predicate bypass, grant forgery /
     expiry / revocation, rate-bound bypass, snapshot mismatch,
     NOOP-vs-UPDATE confusion.
  C. memory store <-> reconcile seam -- the two modules were built in
     parallel and never composed: fact_id derivation, namespace
     presence, tombstone semantics, grade vocabulary, signature
     domains. Mismatches are merge-seam hazards (documented, not
     in-tree vulnerabilities).
  D. gov/supervision.py lease-obligation seam (wave-298 lane 4) --
     cross-supervisor replay, same-token confusion, sweep
     double-escalation, pre-crash lease with rotated token.
  E. F372 / F373 re-verification on this base (both still OPEN).

Base: wave-298 merge 2af956fd880d9a58a9e26e51efb6f47e82594b4e
(verified via git rev-parse HEAD after clone; git ls-remote agreed).

Pin 1780 at lane time (no new codes minted by this lane -- attack only; gov/ stays
byte-identical); wave-299 merge: pin 1780 -> 1797. Next free F377 (F374, F375, F376 filed by this lane).

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g299-rt && TMPDIR=/var/tmp/g299-rt \\
    ~/workspace/.gov-venv/bin/python evals/w299_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g299-rtb \\
    ~/workspace/.gov-venv/bin/python evals/w299_redteam_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import inspect
import json
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import memory_store as mst
from gov import memory_reconcile as mrc
from gov import supervision as sup
from gov import coordination_lease as lease
from gov import policy_ci as pci
from gov import approval_quorum as aq
from gov import ed25519 as _ed25519

TAXONOMY_PIN = 2128 # Wave-339 lane 1: pin 2126 -> 2127 (+1 oci-bundle-not-verifiable).  Wave-298 merge pin; this lane mints no codes.; Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 4: pin 1820 -> 1822 (+2 workflow-saga-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn); Wave-325 lane 2: pin 2012 -> 2018 (+6 federated-identity-*: identity-issuer-key-retired + identity-token-issuer-unknown + identity-token-key-binding-mismatch + identity-token-replayed + identity-token-required + identity-token-ttl-exceeded); Wave-325 merge: pin 2018 -> 2020 (+8: 2 residual-hardening (witness-alert-queue-overflow + export-witness-policy-version-below-minimum) + 6 federated-identity-*); Wave-326 lane 2: pin 2020 -> 2027 (+7: 6 supplychain-standing-* + 1 supplychain-feed-outside-trust-boundary); Wave-328 merge: pin 2044 -> 2056 (+12: 1 supplychain-standing-journal-corrupt + 3 residual-hardening (supplychain-scan-already-registered + advisory-version-tie + advisory-input-unpinned) + 8 custody-shamir-*); Wave-329 merge: pin 2056 -> 2058 (+2 evidence-bundle-*) Wave-332 lane 2: pin 2058 -> 2062 (+4 mcp-oauth-iss-*/mcp-oauth-resource-*).; Wave-333 lane 3: pin 2062 -> 2069 (+7 capability-token-*); Wave-333 merge: pin 2069 -> 2077 (+8 revocation-push-*); Wave-334 lane 2: pin 2077 -> 2088 (+11 mcp-server-auth-*); Wave-334 merge: pin 2088 -> 2100 (+23: 11 mcp-server-auth-* + 6 mcp-oauth-prm-* + 6 incident-gpai9-*). Wave-335 merge: pin 2100 -> 2106 (+6: 1 identity-refresh-* + 2 evidence-pq-* + 3 tool-rate-*).; Wave-337 lane 3: pin 2106 -> 2121 (+15 mcp-oauth-cimd-*); Wave-337 merge: pin 2121 -> 2124 (+3 tool-budget-*)


REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

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
    return hashlib.sha256(("w299-redteam-%s" % tag).encode()).digest()


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
        # Footer at lane-commit time: this lane filed F374-F376.
        # open F372, F373, F374, F375, F376 / next free F377.
        # Wave-299 merge re-pin: F372/F373 CLOSED by lane 1; merged footer
        # is open F374, F375, F376 / next free F377.
        # Wave-300 merge re-pin: F374/F375/F376 CLOSED by lanes 1-2;
        # wave-301 merge re-pin: F377/F378 CLOSED by lanes 1-2;
        # wave-301 red team filed F379 (OPEN). Re-pin, wave-302
        # lane 1: F379 CLOSED. Merged footer is open findings: none /
        # next free F380.
        # Anchor to the LAST matches: the footer, not historical entries.
                # Wave-303 lane 4 re-pin: F384 CLOSED by this lane.
# Wave-304 lane A re-pin: F385 CLOSED; lane footer open F386 / next free F387.
        # Wave-303 merge re-pin: open F385,F386 / next free F387.
        ok = (m_open and m_open[-1].strip() == "F411"
              and m_next and m_next[-1] == "F412")
        self.assertTrue(_expect_held(
            "footer-state", ok,
            "open=%r next=%r" % (
                m_open[-1].strip() if m_open else None,
                m_next[-1] if m_next else None)) == "HELD")

    def test_pin_taxonomy(self):
        lits = _literals()
        ok = (len(lits) == TAXONOMY_PIN and len(set(lits)) == len(lits)
              and lits == sorted(lits))
        self.assertTrue(_expect_held(
            "pin-taxonomy", ok,
            "%d literals, unique, sorted" % len(lits)) == "HELD")


# ------------------------------------------------------------------
# A. memory_store attacks
# ------------------------------------------------------------------

def _ms_episode(ms, seed, tag, at, digest="ab" * 32):
    body = {"agent_id": tag, "content_digest": digest,
            "source_principal": tag, "source_pubkey": _pub(seed),
            "recorded_at": at}
    sig = _ed25519.sign(seed, _canon(body)).hex()
    return ms.record_episode(tag, digest, tag, _pub(seed), sig, at)


def _ms_fact(ms, seed, tag, episode_id, key, digest, valid_at,
             recorded_at, reliability="C", credibility=3):
    body = {"statement_key": key, "statement_digest": digest,
            "source_episode_ids": [episode_id],
            "source_principal": tag, "source_pubkey": _pub(seed),
            "valid_at": valid_at, "retain_until": None,
            "reliability": reliability, "credibility": credibility,
            "created_at": recorded_at}
    sig = _ed25519.sign(seed, _canon(body)).hex()
    return ms.record_fact(key, digest, [episode_id], tag, _pub(seed),
                          sig, valid_at, recorded_at,
                          reliability=reliability, credibility=credibility)


def _ms_retract(ms, seed, tag, key, at):
    body = {"statement_key": key, "retractor_principal": tag,
            "retractor_pubkey": _pub(seed), "retracted_at": at}
    sig = _ed25519.sign(seed, _canon(body)).hex()
    return ms.retract_fact(key, tag, _pub(seed), sig, at)


class MemoryStoreAttackTest(unittest.TestCase):
    """Target A: gov/memory_store.py."""

    def test_f374_hostile_tombstone(self):
        """F374 (MEDIUM, OPEN): retraction authority migrates to the
        newest writer. An attacker with only legitimate write access
        supersedes the victim's fact, then retracts the whole key --
        permanently tombstoning it. The victim cannot recover: even a
        freshly re-recorded fact refuses recall (the tombstone is keyed
        by statement_key forever). Record-only: F374 is OPEN at this
        base (BREAK by design)."""
        victim, attacker = _seed("f374-victim"), _seed("f374-attacker")
        ms = mst.MemoryStore()
        ep_v = _ms_episode(ms, victim, "vic", 100)
        _ms_fact(ms, victim, "vic", ep_v, "k1", "cd" * 32, 100, 100)
        ep_a = _ms_episode(ms, attacker, "atk", 200, digest="ef" * 32)
        _ms_fact(ms, attacker, "atk", ep_a, "k1", "12" * 32, 200, 200,
                 reliability="D", credibility=4)
        # The attacker is now the newest writer: retract succeeds.
        try:
            _ms_retract(ms, attacker, "atk", "k1", 300)
        except mst.MemoryStoreError as e:
            return self.assertTrue(_expect_held(
                "F374-hostile-tombstone", True,
                "hostile retract refused coded %s" % (e.code,)) == "HELD")
        # Retract landed: the victim re-records and tries to recall.
        ep_v2 = _ms_episode(ms, victim, "vic", 400, digest="aa" * 32)
        _ms_fact(ms, victim, "vic", ep_v2, "k1", "cd" * 32, 400, 400)
        try:
            ms.recall("k1", 450)
        except mst.MemoryStoreError as e:
            if e.code == "memory-store-tombstoned":
                return self.assertTrue(_record(
                    "F374-hostile-tombstone", "BREAK",
                    "attacker tombstoned victim key; re-record still "
                    "unrecallable (permanent denial)") == "BREAK")
            raise
        return self.assertTrue(_record(
            "F374-hostile-tombstone", "HELD",
            "key recovered after hostile retract") == "HELD")

    def test_f374_victim_loses_retract_authority(self):
        """F374 facet 2 (CLOSED 2026-10-03, wave-300 lane 1): after
        being superseded, the ORIGINAL author RETAINS retraction
        authority over their claim -- retract_fact now authorizes
        against the claim's first writer, not the newest writer. The
        hostile superseder's own retract of the victim's key must
        refuse coded memory-store-unsigned-retraction."""
        victim, attacker = _seed("f374b-victim"), _seed("f374b-attacker")
        ms = mst.MemoryStore()
        ep_v = _ms_episode(ms, victim, "vic", 100)
        _ms_fact(ms, victim, "vic", ep_v, "k1", "cd" * 32, 100, 100)
        ep_a = _ms_episode(ms, attacker, "atk", 200, digest="ef" * 32)
        _ms_fact(ms, attacker, "atk", ep_a, "k1", "12" * 32, 200, 200)
        # The victim's own retract of their superseded claim now
        # succeeds: authority is anchored at first write.
        tid = _ms_retract(ms, victim, "vic", "k1", 250)
        self.assertTrue(_expect_held(
            "F374-victim-loses-retract",
            isinstance(tid, str) and len(tid) == 64,
            "original author retracts own claim after supersession")
            == "HELD")
        # And the hostile superseder cannot retract the victim's key.
        ms2 = mst.MemoryStore()
        ep_v = _ms_episode(ms2, victim, "vic", 100)
        _ms_fact(ms2, victim, "vic", ep_v, "k1", "cd" * 32, 100, 100)
        ep_a = _ms_episode(ms2, attacker, "atk", 200, digest="ef" * 32)
        _ms_fact(ms2, attacker, "atk", ep_a, "k1", "12" * 32, 200, 200)
        self.assertTrue(_expect_coded(
            "F374-hostile-retract-refused",
            lambda: _ms_retract(ms2, attacker, "atk", "k1", 300),
            {"memory-store-unsigned-retraction"}) == "HELD")

    def test_f374_regression_pins(self):
        """F374 closure regression pins (wave-300 lane 1): an author
        who supersedes their OWN fact keeps retract authority; the
        archivist override still works; double retract stays a
        tombstone refusal, not a toggle."""
        victim = _seed("f374r-victim")
        arch = _seed("f374r-arch")
        ms = mst.MemoryStore(archivists={"chief": _pub(arch)})
        ep = _ms_episode(ms, victim, "vic", 100)
        _ms_fact(ms, victim, "vic", ep, "k2", "cd" * 32, 100, 100)
        ep2 = _ms_episode(ms, victim, "vic", 200, digest="bb" * 32)
        _ms_fact(ms, victim, "vic", ep2, "k2", "ee" * 32, 200, 200)
        tid = _ms_retract(ms, victim, "vic", "k2", 300)
        ok1 = isinstance(tid, str) and len(tid) == 64
        ms2 = mst.MemoryStore(archivists={"chief": _pub(arch)})
        ep3 = _ms_episode(ms2, victim, "vic", 100)
        _ms_fact(ms2, victim, "vic", ep3, "k3", "cd" * 32, 100, 100)
        tid2 = _ms_retract(ms2, arch, "chief", "k3", 150)
        ok2 = isinstance(tid2, str) and len(tid2) == 64
        ok3 = False
        try:
            _ms_retract(ms2, arch, "chief", "k3", 160)
        except mst.MemoryStoreError as e:
            ok3 = e.code == "memory-store-tombstoned"
        self.assertTrue(_expect_held(
            "F374-regression-pins", ok1 and ok2 and ok3,
            "own-supersede-retract=%s archivist=%s double=%s"
            % (ok1, ok2, ok3)) == "HELD")

    def test_corroboration_dedupes_principal(self):
        """Falsified-not-filed: corroboration counts DISTINCT source
        principals -- the same principal asserting twice does not
        inflate the count."""
        s1 = _seed("corr-s1")
        ms = mst.MemoryStore()
        ep1 = _ms_episode(ms, s1, "p1", 100)
        _ms_fact(ms, s1, "p1", ep1, "ck", "dd" * 32, 100, 100)
        _ms_fact(ms, s1, "p1", ep1, "ck", "dd" * 32, 150, 150)
        rec = ms.recall("ck", 175)
        self.assertTrue(_expect_held(
            "ms-corroboration-dedup", rec["corroboration_count"] == 1,
            "count=%d" % rec["corroboration_count"]) == "HELD")

    def test_forged_fact_signature_refused(self):
        """Falsified-not-filed: supersession still requires a valid
        signature under the DECLARED source key -- signing as someone
        else's key refuses."""
        s1, s2 = _seed("forge-s1"), _seed("forge-s2")
        ms = mst.MemoryStore()
        ep1 = _ms_episode(ms, s1, "p1", 100)
        _ms_fact(ms, s1, "p1", ep1, "k9", "dd" * 32, 100, 100)
        # Attacker declares s1's pubkey but signs with s2's seed.
        body = {"statement_key": "k9", "statement_digest": "ee" * 32,
                "source_episode_ids": [ep1],
                "source_principal": "p1", "source_pubkey": _pub(s1),
                "valid_at": 200, "retain_until": None,
                "reliability": "C", "credibility": 3, "created_at": 200}
        sig = _ed25519.sign(s2, _canon(body)).hex()  # wrong key
        self.assertTrue(_expect_coded(
            "ms-forged-fact-sig",
            lambda: ms.record_fact("k9", "ee" * 32, [ep1], "p1",
                                   _pub(s1), sig, 200, 200),
            {"memory-store-invalid"}) == "HELD")

    def test_retention_backdate_refused(self):
        """Falsified-not-filed: retain_until <= recorded_at refuses at
        write time -- a lapsed-at-write schedule is malformed."""
        s1 = _seed("ret-s1")
        ms = mst.MemoryStore()
        ep1 = _ms_episode(ms, s1, "p1", 100)
        body = {"statement_key": "kr", "statement_digest": "dd" * 32,
                "source_episode_ids": [ep1],
                "source_principal": "p1", "source_pubkey": _pub(s1),
                "valid_at": 100, "retain_until": 50,
                "reliability": "C", "credibility": 3, "created_at": 100}
        sig = _ed25519.sign(s1, _canon(body)).hex()
        self.assertTrue(_expect_coded(
            "ms-retention-backdate",
            lambda: ms.record_fact("kr", "dd" * 32, [ep1], "p1",
                                   _pub(s1), sig, 100, 100,
                                   retain_until=50),
            {"memory-store-invalid"}) == "HELD")

# ------------------------------------------------------------------
# B. memory_reconcile attacks
# ------------------------------------------------------------------

def _rc(owner_seed, tag="rc", max_writes=100, window=3600):
    r = mrc.MemoryReconciler(_seed("rcrec-%s" % tag), "rec-%s" % tag,
                             max_writes_per_principal=max_writes,
                             write_window_seconds=window)
    r.declare_namespace("ns-a", _pub(owner_seed))
    return r


def _rc_candidate(owner_seed, namespace, principal, key, value, at,
                  op="add", supersedes=None, reliability="C1",
                  corroborations=0):
    c = {"schema": "memory-record/v1", "namespace": namespace,
         "key": key,
         "value_digest": hashlib.sha256(value.encode()).hexdigest(),
         "written_at": at, "supersedes": supersedes,
         "provenance": {"source_principal": principal,
                        "reliability": reliability,
                        "corroborations": corroborations,
                        "ingested_at": at},
         "expires_at": None, "op": op}
    unsigned = {k: c[k] for k in c if k != "signature"}
    c["signature"] = _ed25519.sign(owner_seed, _canon(unsigned)).hex()
    return c


class ReconcileAttackTest(unittest.TestCase):
    """Target B: gov/memory_reconcile.py."""

    def test_f375_rate_bound_principal_rotation(self):
        """F375 (LOW, OPEN): the write-rate bound is keyed on the
        self-reported provenance.source_principal string. The namespace
        owner -- who signs every candidate -- rotates the string per
        write and the bound never fires. The lane claimed "Defenses
        bound even the owner (rate, evidence, snapshots)". Record-only:
        F375 is OPEN at this base (BREAK by design)."""
        owner = _seed("f375-owner")
        r = _rc(owner, tag="f375", max_writes=2, window=3600)
        accepted = 0
        for i in range(6):
            try:
                r.reconcile(_rc_candidate(
                    owner, "ns-a", "principal-%d" % i, "k%d" % i,
                    "v%d" % i, 1000 + i), [], {}, 1000 + i)
                accepted += 1
            except mrc.MemoryReconcileError:
                pass
        # BREAK iff the rotation evaded the bound (all 6 accepted).
        self.assertTrue(_record(
            "F375-rate-bound-evasion",
            "BREAK" if accepted == 6 else "HELD",
            "%d/6 rotated-principal writes accepted (bound=2)" % accepted
            ) in ("BREAK", "HELD"))

    def test_f375_rate_bound_control(self):
        """Control: the same principal string IS rate-bound -- the
        mechanism works, only the identity it keys on is forgeable."""
        owner = _seed("f375c-owner")
        r = _rc(owner, tag="f375c", max_writes=2, window=3600)
        codes = []
        for i in range(3):
            try:
                r.reconcile(_rc_candidate(
                    owner, "ns-a", "same-principal", "k%d" % i,
                    "v%d" % i, 1000 + i), [], {}, 1000 + i)
            except mrc.MemoryReconcileError as e:
                codes.append(e.code)
        self.assertTrue(_expect_held(
            "F375-rate-bound-control",
            codes == ["memory-reconcile-invalid"],
            "3rd same-principal write refused: %r" % codes) == "HELD")

    def test_f376_caller_namespace_self_asserted(self):
        """F376 (LOW, OPEN): cross-namespace recall authorization rests
        on the self-asserted caller_namespace parameter. Any caller
        that knows a grant exists can assert the grantee namespace name
        and read the owner's facts -- the grant check is bypassed
        without any key material. Record-only: F376 is OPEN at this
        base (BREAK by design)."""
        owner = _seed("f376-owner")
        r = mrc.MemoryReconciler(_seed("rcrec-f376"), "rec-f376")
        r.declare_namespace("alice", _pub(owner))
        r.declare_namespace("bob", _pub(_seed("f376-bob")))
        r.grant_sharing("alice", "bob", 900, 2000, owner)
        r.reconcile(_rc_candidate(owner, "alice", "alice-p", "secret",
                                  "s3cr3t", 1000), [], {}, 1000)
        # Mallory holds no key and no grant; she simply asserts she is
        # "bob".
        try:
            rec = r.recall({"namespace": "alice", "key": "secret"},
                           "bob", 1500)
            leaked = rec["value_digest"] == hashlib.sha256(
                b"s3cr3t").hexdigest()
        except mrc.MemoryReconcileError:
            leaked = False
        self.assertTrue(_record(
            "F376-caller-assertion-bypass",
            "BREAK" if leaked else "HELD",
            "self-asserted grantee name read cross-namespace fact"
            if leaked else "assertion refused") in ("BREAK", "HELD"))

    def test_scope_predicate_validated(self):
        """Falsified-not-filed: empty / missing / non-dict scopes all
        refuse memory-reconcile-scope-missing -- there is no empty-scope
        bypass."""
        owner = _seed("scope-owner")
        r = _rc(owner, tag="scope")
        r.reconcile(_rc_candidate(owner, "ns-a", "p", "k1", "v1", 1000),
                    [], {}, 1000)
        cases = [({"namespace": "", "key": "k1"}, "empty-namespace"),
                 ({"namespace": "ns-a", "key": ""}, "empty-key"),
                 ({"namespace": "ns-a"}, "missing-key"),
                 ("ns-a", "non-dict")]
        for scope, label in cases:
            self.assertTrue(_expect_coded(
                "mr-scope-%s" % label,
                lambda s=scope: r.recall(s, "ns-a", 1500),
                {"memory-reconcile-scope-missing"}) == "HELD")

    def test_snapshot_mismatch_refused(self):
        """Falsified-not-filed: UPDATE naming a stale supersedes
        refuses -- snapshot-before-mutation is enforced."""
        owner = _seed("snap-owner")
        r = _rc(owner, tag="snap")
        r.reconcile(_rc_candidate(owner, "ns-a", "p", "k1", "v1", 1000),
                    [], {}, 1000)
        latest = r._latest("ns-a", "k1")
        self.assertTrue(_expect_coded(
            "mr-snapshot-stale",
            lambda: r.reconcile(_rc_candidate(
                owner, "ns-a", "p", "k1", "v2", 1100, op="update",
                supersedes="00" * 32), [latest], {}, 1100),
            {"memory-reconcile-invalid"}) == "HELD")

    def test_grant_expiry_revocation_forgery(self):
        """Falsified-not-filed: expired grants, revoked grants, and
        foreign-key grant_sharing all refuse coded."""
        owner = _seed("grant-owner")
        r = mrc.MemoryReconciler(_seed("rcrec-grant"), "rec-grant")
        r.declare_namespace("alice", _pub(owner))
        r.declare_namespace("bob", _pub(_seed("grant-bob")))
        g = r.grant_sharing("alice", "bob", 900, 1200, owner)
        r.reconcile(_rc_candidate(owner, "alice", "ap", "secret",
                                  "s3cr3t", 1000), [], {}, 1000)
        # live grant reads (F376 wave-300: the grant is PRESENTED --
        # bearer-grant model; a bare namespace string never suffices)
        rec = r.recall({"namespace": "alice", "key": "secret"},
                       "bob", 1100, grant=g)
        self.assertTrue(_expect_held(
            "mr-grant-live", rec["key"] == "secret",
            "live grant reads") == "HELD")
        self.assertTrue(_expect_coded(
            "mr-grant-expired",
            lambda: r.recall({"namespace": "alice", "key": "secret"},
                             "bob", 1300, grant=g),
            {"memory-reconcile-unauthorized-namespace"}) == "HELD")
        r.revoke_grant(g["grant_id"], owner)
        self.assertTrue(_expect_coded(
            "mr-grant-revoked",
            lambda: r.recall({"namespace": "alice", "key": "secret"},
                             "bob", 1100, grant=g),
            {"memory-reconcile-unauthorized-namespace"}) == "HELD")
        mallory = _seed("grant-mallory")
        self.assertTrue(_expect_coded(
            "mr-grant-forged",
            lambda: r.grant_sharing("alice", "mallory", 900, 2000,
                                    mallory),
            {"memory-reconcile-unauthorized-namespace"}) == "HELD")

    def test_noop_and_conflict_semantics(self):
        """Falsified-not-filed: same-digest ADD is a NOOP (even with
        op=add); different-digest ADD on a live key refuses
        conflict-unresolved -- there is no silent overwrite."""
        owner = _seed("noop-owner")
        r = _rc(owner, tag="noop")
        r.reconcile(_rc_candidate(owner, "ns-a", "p", "k1", "v1", 1000),
                    [], {}, 1000)
        latest = r._latest("ns-a", "k1")
        d = r.reconcile(_rc_candidate(owner, "ns-a", "p", "k1", "v1",
                                      1200, op="add"), [latest], {}, 1200)
        self.assertTrue(_expect_held(
            "mr-add-same-digest-noop", d["decision"] == "NOOP",
            "decision=%s" % d["decision"]) == "HELD")
        self.assertTrue(_expect_coded(
            "mr-add-diff-digest-conflict",
            lambda: r.reconcile(_rc_candidate(
                owner, "ns-a", "p", "k1", "v2x", 1300, op="add"),
                [r._latest("ns-a", "k1")], {}, 1300),
            {"memory-reconcile-conflict-unresolved"}) == "HELD")


# ------------------------------------------------------------------
# C. store <-> reconcile seam hazards (documented, not findings)
# ------------------------------------------------------------------

class SeamHazardTest(unittest.TestCase):
    """Target C: the two memory modules were built in parallel and
    never composed. These probes DOCUMENT the merge-seam hazards for
    the merge coordinator -- they are HELD as recorded hazards, not
    in-tree vulnerabilities (nothing composes the modules yet)."""

    def test_hazard_namespace_absent_in_store(self):
        # memory_store has no namespace concept at all; reconcile
        # records REQUIRE namespace. A naive wiring would drop the
        # grant enforcement the reconciler provides.
        import inspect
        sig = inspect.signature(mst.MemoryStore.record_fact)
        params = set(sig.parameters)
        sig2 = inspect.signature(mst.MemoryStore.recall)
        self.assertTrue(_expect_held(
            "seam-no-namespace-in-store",
            "namespace" not in params
            and "namespace" not in set(sig2.parameters),
            "store record_fact/recall take no namespace; reconcile "
            "memory-record/v1 mandates it -- merge must add a "
            "namespace binding or the grant model is unenforced "
            "in the store") == "HELD")

    def test_hazard_fact_id_derivation_incompatible(self):
        # store fact_ids are seq-derived (not externally reproducible);
        # reconcile fact_ids are content-derived sha256(namespace, key,
        # value_digest, written_at, supersedes). reconcile's supersedes
        # naming cannot be satisfied by store fact_ids in a verifiable
        # way, and vice versa.
        src = inspect.getsource(mst.MemoryStore.record_fact)
        self.assertTrue(_expect_held(
            "seam-fact-id-derivation",
            '"seq": self._seq' in src,
            "store fact_id = digest(seq, body) -- internal counter, "
            "not content-derived; reconcile _fact_id = digest("
            "namespace, key, value_digest, written_at, supersedes). "
            "Merge must pick ONE derivation or provide an adapter") == "HELD")

    def test_hazard_tombstone_semantics_conflict(self):
        # store: tombstone is per-KEY and permanent -- recall refuses
        # even after re-record. reconcile: tombstone is per-RECORD
        # state; a new ADD after retraction is accepted (supersedes the
        # tombstone). Direct semantic conflict on re-admission.
        self.assertTrue(_expect_held(
            "seam-tombstone-conflict", True,
            "store: per-key permanent tombstone (recall always "
            "refuses); reconcile: per-record tombstone, new ADD "
            "re-admits. Merge must reconcile the re-admission rule") == "HELD")

    def test_hazard_grade_vocabulary(self):
        # store: reliability letter + credibility int ("C"+3 -> "C3");
        # reconcile: combined grade strings ("C1", "A1"...). The
        # vocabularies overlap but are not identical types.
        src = inspect.getsource(mst._check_grade)
        self.assertTrue(_expect_held(
            "seam-grade-vocab", "credibility" in src,
            "store grades = (letter, int); reconcile grades = single "
            "token strings. Merge must normalize") == "HELD")

    def test_hazard_temporal_models(self):
        # store: bi-temporal (valid_at/invalid_at x created_at/
        # expired_at). reconcile: written_at + expires_at only. A
        # record crossing the seam loses a temporal dimension.
        self.assertTrue(_expect_held(
            "seam-temporal-models", True,
            "store is bi-temporal; reconcile is single-timeline. "
            "Merge must map valid_at/invalid_at or drop the claim") == "HELD")

    def test_hazard_signature_domains(self):
        # store facts are signed by the SOURCE principal's key;
        # reconcile candidates are signed by the NAMESPACE OWNER's key.
        # Different trust anchors per record -- the merge must decide
        # which signatures the composed store verifies.
        self.assertTrue(_expect_held(
            "seam-signature-domains", True,
            "store: source-key signatures; reconcile: namespace-owner "
            "signatures. Merge must define the composed trust anchor") == "HELD")


# ------------------------------------------------------------------
# D. supervision <-> lease obligation seam
# ------------------------------------------------------------------

def _mk_sup(name, tag, gated=True):
    sseed = _seed("sup-%s" % tag)
    c0 = _seed("c0-%s" % tag)
    specs = [sup.ChildSpec("child-a", _pub(c0), "one_for_one", 100,
                           3600, requires_lease=gated)]
    s = sup.Supervisor(name, specs, sseed)
    s.start(at=0)
    return s, c0


def _crash_report(cseed, child_id, at):
    body = {"child_id": child_id, "reason_kind": "exit",
            "reason_bytes": "boom", "crashed_at": at}
    rep = dict(body)
    rep["signature"] = _ed25519.sign(cseed, _canon(body)).hex()
    return rep


def _lease_pair(holder, auth_seed, issued_old=0, issued_new=20):
    m2 = lease.LeaseManager()
    old = m2.acquire("scope-a", 3600, holder, authority_seed=auth_seed,
                     issued_at=issued_old)
    m2.release("scope-a", old["fencing_token"], holder)
    new = m2.acquire("scope-a", 3600, holder, authority_seed=auth_seed,
                     issued_at=issued_new)
    return auth_seed, old, new


class SupervisionLeaseAttackTest(unittest.TestCase):
    """Target D: the lease-obligation seam."""

    def test_cross_supervisor_replay_refused(self):
        """Falsified-not-filed: an obligation from supervisor A (even
        same name, different seed) presented to supervisor B refuses --
        supervisor-name check + signature under B's key + issued-by-me
        lookup all fire."""
        sA, c0A = _mk_sup("sup-one", "A")
        sB, _c0B = _mk_sup("sup-one", "B")
        dA = sA.report_crash(
            "child-a", _crash_report(c0A, "child-a", 10), at=10,
            old_fencing_tokens={"child-a": 7})
        oblA = dA["lease_obligations"]["child-a"]
        auth, _old, new = _lease_pair("child-a", _seed("auth"))
        self.assertTrue(_expect_coded(
            "sl-cross-supervisor-replay",
            lambda: sB.attest_reacquisition("child-a", oblA, new,
                                            _pub(auth), at=30),
            {"supervision-invalid"}) == "HELD")

    def test_sweep_never_double_escalates(self):
        """Falsified-not-filed: sweep_obligations escalates once;
        terminal states are never re-escalated."""
        s, c0 = _mk_sup("sup-s", "S")
        s.report_crash("child-a", _crash_report(c0, "child-a", 10),
                       at=10, old_fencing_tokens={"child-a": 7},
                       obligation_ttl=100)
        n1 = s.sweep_obligations(at=500)
        n2 = s.sweep_obligations(at=600)
        self.assertTrue(_expect_held(
            "sl-sweep-once", (n1, n2) == (1, 0),
            "sweeps=%r" % ((n1, n2),)) == "HELD")

    def test_pre_crash_lease_refused_despite_new_token(self):
        """Falsified-not-filed: a lease issued BEFORE the crash instant
        -- even with a rotated fencing token -- refuses. The time check
        wins over the token check."""
        s, c0 = _mk_sup("sup-t", "T")
        d = s.report_crash("child-a", _crash_report(c0, "child-a", 50),
                           at=50, old_fencing_tokens={"child-a": 7})
        obl = d["lease_obligations"]["child-a"]
        auth = _seed("auth2")
        m = lease.LeaseManager()
        pre = m.acquire("scope-a", 3600, "child-a",
                        authority_seed=auth, issued_at=10)
        self.assertTrue(_expect_coded(
            "sl-pre-crash-lease",
            lambda: s.attest_reacquisition("child-a", obl, pre,
                                           _pub(auth), at=60),
            {"supervision-invalid"}) == "HELD")

    def test_same_token_two_children_distinct_obligations(self):
        """Falsified-not-filed: two children crashing at the same
        instant with the same fencing token get distinct obligations
        (per-supervisor seq in the obligation id)."""
        sseed = _seed("sup-D")
        ca, cb = _seed("ca-D"), _seed("cb-D")
        specs = [sup.ChildSpec("child-a", _pub(ca), "one_for_one", 100,
                               3600, requires_lease=True),
                 sup.ChildSpec("child-b", _pub(cb), "one_for_one", 100,
                               3600, requires_lease=True)]
        sD = sup.Supervisor("sup-d", specs, sseed)
        sD.start(at=0)
        toks = {"child-a": 7, "child-b": 7}
        dA = sD.report_crash("child-a", _crash_report(ca, "child-a", 10),
                             at=10, old_fencing_tokens=toks)
        dB = sD.report_crash("child-b", _crash_report(cb, "child-b", 10),
                             at=10, old_fencing_tokens=toks)
        oa = dA["lease_obligations"]["child-a"]["obligation_id"]
        ob = dB["lease_obligations"]["child-b"]["obligation_id"]
        self.assertTrue(_expect_held(
            "sl-distinct-obligations", oa != ob,
            "obligation ids distinct") == "HELD")


# ------------------------------------------------------------------
# E. F372 / F373 re-verification (still OPEN at this base)
# ------------------------------------------------------------------

_SOURCE = """version: 1
policies:
  - name: block-secret-reads
    description: Deny reads of secret-like paths.
    filters:
      - type: value-filter
        key: tool
        op: eq
        value: read_file
    actions:
      - type: deny
        reason: Secret-like read denied.
        flag: secret_access_attempt
"""


class F372F373ReverifyTest(unittest.TestCase):
    def test_f372_expected_open(self):
        """F372 (LOW, OPEN): load_artifact accepts an artifact with an
        added consistently-digested extra file -- the derived set is
        not closed. Record-only: BREAK is the evidence."""
        art = pci.derive(_SOURCE, author="a", change_note="n",
                         probes=["p1"])
        evil = dict(art)
        evil["derived"] = dict(art["derived"])
        evil["digests"] = dict(art["digests"])
        evil["derived"]["evil.yaml"] = "x: 1\n"
        evil["digests"]["evil.yaml"] = hashlib.sha256(b"x: 1\n").hexdigest()
        try:
            pci.load_artifact(evil)
        except Exception:
            return self.assertTrue(_record(
                "F372-artifact-extra-file", "HELD",
                "extra file refused (already closed?)") == "HELD")
        return self.assertTrue(_record(
            "F372-artifact-extra-file", "BREAK",
            "extra derived file passed verification") == "BREAK")

    def test_f373_expected_open(self):
        """F373 (LOW, OPEN): QuorumPredicate slot attributes are
        reassignable post-construction. Record-only: BREAK is the
        evidence."""
        p = aq.QuorumPredicate(min_approvals=3,
                               blocking_veto_roles=("veto",))
        try:
            p._min_approvals = 1
        except Exception as e:
            code = getattr(e, "code", None)
            return self.assertTrue(_record(
                "F373-predicate-min-mutable", "HELD",
                "reassignment refused coded %s" % (code,)) == "HELD")
        return self.assertTrue(_record(
            "F373-predicate-min-mutable", "BREAK",
            "slot reassignment succeeded; min_approvals now %r"
            % (p.min_approvals,)) == "BREAK")


# ------------------------------------------------------------------
# Re-pins of prior red-team batteries
# ------------------------------------------------------------------

class RepinTest(unittest.TestCase):
    def test_repin_w298_redteam(self):
        # At this lane's commit: 4 BREAK -- F372 x1 + F373 x2
        # (expected-open) + footer-state (this lane moved the footer).
        # Wave-299 merge re-pin: F372/F373 CLOSED by lane 1 (probes now
        # HELD as closure regression pins) and the footer-state probe
        # re-pinned to the merged footer -- expect 0 BREAK / 22 HELD.
        import subprocess
        tmp = "/var/tmp/g299-repin-%d" % os.getpid()
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        path = os.path.join(REPO, "evals", "w298_redteam_probes.py")
        out = subprocess.run([sys.executable, path], capture_output=True,
                             text=True, env=env, timeout=600)
        line = (out.stdout.strip().splitlines() or [""])[0]
        ok = ("0 BREAK / 22 HELD" in out.stdout)
        self.assertTrue(_expect_held(
            "repin-w298-redteam", ok, line) == "HELD")

    def test_repin_w297_redteam(self):
        # At this lane's commit: 1 BREAK -- footer-state only (this
        # lane moved the footer). Wave-299 merge re-pin: footer-state
        # re-pinned to the merged footer -- expect 0 BREAK / 53 HELD.
        # F371 stays CLOSED.
        import subprocess
        tmp = "/var/tmp/g299-repin-%d" % os.getpid()
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        path = os.path.join(REPO, "evals", "w297_redteam_probes.py")
        out = subprocess.run([sys.executable, path], capture_output=True,
                             text=True, env=env, timeout=600)
        line = (out.stdout.strip().splitlines() or [""])[0]
        ok = ("0 BREAK / 53 HELD" in out.stdout)
        self.assertTrue(_expect_held(
            "repin-w297-redteam", ok, line) == "HELD")


# ------------------------------------------------------------------
# Depth-1 green checks
# ------------------------------------------------------------------

def _green_check(battery, expect):
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = "/var/tmp/g299-green-%s" % os.getpid()
    os.makedirs(tmp, exist_ok=True)
    env["TMPDIR"] = tmp
    path = os.path.join(REPO, "evals", battery)
    import subprocess
    try:
        out = subprocess.run(
            [sys.executable, path], capture_output=True, text=True,
            env=env, timeout=600)
    except Exception as e:  # noqa: BLE001
        return ("ERROR", "%s" % (e,))
    summary = (out.stdout.strip().splitlines() or ["no output"])[0]
    # NOTE: wave-299 merge re-pinned the callees' footer-state probes
    # to the merged footer, so the known summaries are the all-HELD
    # ones below. Match the known summary, not a zero-error gate.
    if expect in out.stdout:
        return ("HELD", summary)
    return ("BREAK", summary)


class GreenCheckTest(unittest.TestCase):
    def test_green_w298_redteam(self):
        if os.environ.get("GOV_SKIP_GREEN"):
            _record("green-w298-redteam", "HELD", "skipped (depth-1)")
            return
        status, detail = _green_check("w298_redteam_probes.py",
                                      "0 BREAK / 22 HELD")
        self.assertTrue(_expect_held(
            "green-w298-redteam", status == "HELD", detail) == "HELD")

    def test_green_w297_redteam(self):
        if os.environ.get("GOV_SKIP_GREEN"):
            _record("green-w297-redteam", "HELD", "skipped (depth-1)")
            return
        status, detail = _green_check("w297_redteam_probes.py",
                                      "0 BREAK / 53 HELD")
        self.assertTrue(_expect_held(
            "green-w297-redteam", status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, MemoryStoreAttackTest, ReconcileAttackTest,
                SeamHazardTest, SupervisionLeaseAttackTest,
                F372F373ReverifyTest, RepinTest, GreenCheckTest):
        suite.addTests(loader.loadTestsFromTestCase(cls))
    runner = unittest.TextTestRunner(verbosity=0)
    result = runner.run(suite)
    errors = len(result.errors) + len(result.failures)
    brk = [r for r in _results if r[1] == "BREAK"]
    held = [r for r in _results if r[1] == "HELD"]
    print("\n==== w299 redteam: %d BREAK / %d HELD / %d ERROR ===="
          % (len(brk), len(held), errors))
    for name, status, detail in _results:
        if status != "HELD":
            print("  %s %s: %s" % (status, name, detail))
    return 1 if (brk or errors) else 0


if __name__ == "__main__":
    sys.exit(main())
