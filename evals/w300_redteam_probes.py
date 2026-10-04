"""Wave-300 independent red-team battery: wave-299 delegation stack under attack.

Targets:
  A. Receipt-shape adapters -- the wave-299 merge reconciled three
     incompatible receipt shapes with lane 2's native shape canonical
     plus native-aware paths in revocation/identity/tickets. Probes:
     cross-shape confusion (local-shape receipt through native paths
     and vice versa -- must refuse coded, never silently accept).
  B. Ticket<->receipt composition -- a ticket anchored on a receipt
     that is later REVOKED: does presentation check revocation?
     (``present()`` takes no revocation input at all.)
  C. gov/supervision.py capability manifests -- endowment confusion,
     exercise() on routed capabilities, manifest deep-copy mutation,
     expose->offer cycles.
  D. Identity evidence chains -- DID trust-root handling in the two
     offline verifiers, witness coverage, quote-byte shape checks,
     per-link DID independence.
  E. F374 / F375 / F376 re-verification on this base (all still OPEN).

Base: wave-299 merge a830f65f80e9317aa7ae65b83b7eb14b3922bd0e
(verified via git rev-parse HEAD after clone; git ls-remote agreed).

Pin 1812 at lane time (no new codes minted by this lane -- attack only; gov/ stays
byte-identical). Next free F379 at wave-300 merge.

$0 spend, synthetic/local, deterministic. Stdlib only, no in-repo git
subprocesses. New batteries set deployment mode at module level and are
also verified under a clean environment.

Run:
  mkdir -p /var/tmp/g300-rt && TMPDIR=/var/tmp/g300-rt \\
    ~/workspace/.gov-venv/bin/python evals/w300_redteam_probes.py
Also standalone (clean env):
  env -u GOV_DEPLOYMENT_MODE TMPDIR=/var/tmp/g300-rtb \\
    ~/workspace/.gov-venv/bin/python evals/w300_redteam_probes.py
"""

import os

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

import hashlib
import json
import re
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gov import delegation as dg
from gov import delegation_tickets as tkt
from gov import delegation_revocation as rv
from gov import delegation_identity as di
from gov import supervision as sup
from gov import memory_store as mst
from gov import memory_reconcile as mrc
from gov import ed25519 as _ed25519

TAXONOMY_PIN = 2012 # Wave-301 merge pin 1812 (was 1802 at wave-300); this lane mints no codes.; Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 lane 4: pin 1820 -> 1822 (+2 workflow-saga-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)



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
    return hashlib.sha256(("w300-redteam-%s" % tag).encode()).digest()


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
        # Wave-300 merge re-pin: F374/F375/F376 CLOSED by lanes 1-2.
        # Wave-301 merge re-pin: F377/F378 CLOSED by lanes 1-2;
        # wave-301 red team filed F379 (OPEN). Re-pin, wave-302
        # lane 1: F379 CLOSED. Merged footer is open findings: none /
        # next free F380.
        # Anchor to the LAST matches: the footer, not historical entries.
                # Wave-303 lane 4 re-pin: F384 CLOSED by this lane.
# Wave-304 lane A re-pin: F385 CLOSED; lane footer open F386 / next free F387.
        # Wave-303 merge re-pin: open F385,F386 / next free F387.
        ok = (m_open and m_open[-1].strip() == "none"
              and m_next and m_next[-1] == "F409")
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
# Shared delegation fixtures
# ------------------------------------------------------------------

def _native_chain(tag="a"):
    """root -> mid -> leaf native receipt chain; returns dict of parts."""
    rs, ms, ls = _seed(tag + "-root"), _seed(tag + "-mid"), _seed(tag + "-leaf")
    rp, mp, lp = _pub(rs), _pub(ms), _pub(ls)
    cons = {"expires_at": 10 ** 12, "max_depth": 8}
    root = dg.issue(rs, "root-" + tag, "mid-" + tag, mp, {"memory.read"},
                    constraints=dict(cons))
    mid = dg.issue(ms, "mid-" + tag, "leaf-" + tag, lp, {"memory.read"},
                   parent=root, constraints=dict(cons))
    return {"seeds": {"root": rs, "mid": ms, "leaf": ls},
            "pubs": {"root": rp, "mid": mp, "leaf": lp},
            "chain": [root, mid]}


def _did_doc(did, controller_seed, delegation_pubkeys, at=100):
    return di.issue_did_document(did, controller_seed, delegation_pubkeys, at)


def _did_evidence(receipt_digest, did, doc, controller_seed):
    return di.make_identity_evidence(
        "did", receipt_digest, did=did,
        did_document_digest=di.did_document_digest(doc),
        controller_seed=controller_seed)


# ------------------------------------------------------------------
# F377: embedded DID documents override verifier trust roots
# ------------------------------------------------------------------

class F377DIDTrustRootTest(unittest.TestCase):
    """F377 (MEDIUM, OPEN): in both offline chain verifiers
    (``verify_native_chain_offline`` and ``verify_chain_offline``),
    an EMBEDDED DID document silently REPLACES the verifier's own
    pinned trust root for the same DID (``roots[did] = doc``). The
    embedded document is only "re-verified" by checking its
    controller self-signature -- which is always valid for an
    attacker-controlled DID. An attacker holding any link in a chain
    can therefore export a chain document whose forged embedded DID
    doc makes the verifier believe the attacker's key is bound to
    someone else's DID. OPEN at this base (BREAK by design)."""

    def test_F377_native_embedded_overrides_pinned(self):
        fx = _native_chain("f377n")
        chain = fx["chain"]
        leaf = chain[-1]
        # Victor's pinned trust root: the REAL did:example:alice document.
        alice_ctrl = _seed("f377n-alice-ctrl")
        alice_key = _seed("f377n-alice-key")
        real_doc = _did_doc("did:example:alice", alice_ctrl,
                            [_pub(alice_key)])
        # Mallory (the mid delegatee, signer of the leaf) forges a
        # did:example:alice document naming HER key.
        mallory_ctrl = _seed("f377n-mallory-ctrl")
        forged_doc = _did_doc("did:example:alice", mallory_ctrl,
                              [fx["pubs"]["mid"]])
        ev = _did_evidence(leaf["receipt_id"], "did:example:alice",
                           forged_doc, mallory_ctrl)
        entries = [
            {"receipt": chain[0], "identity_evidence": None,
             "did_documents": {}},
            {"receipt": leaf, "identity_evidence": ev,
             "did_documents": {"did:example:alice": forged_doc}},
        ]
        doc = di.export_native_chain(entries, fx["seeds"]["mid"], 200, 200,
                                     [fx["pubs"]["root"]])
        try:
            rec = di.verify_native_chain_offline(
                doc, 200,
                trusted_did_docs={"did:example:alice": real_doc},
                trust_roots=[fx["pubs"]["root"]])
        except Exception as e:  # noqa: BLE001
            return self.assertTrue(_expect_held(
                "F377-native-override", True,
                "forged embedded doc refused coded %s"
                % getattr(e, "code", "?")) == "HELD")
        # Verified despite Victor pinning the real document: the
        # embedded forgery silently replaced his trust root.
        self.assertTrue(_expect_held(
            "F377-native-override", not rec.get("verified"),
            "offline verify accepted forged embedded DID doc") == "BREAK")

    def test_F377_local_embedded_overrides_pinned(self):
        # Same flaw in the local-shape verify_chain_offline path.
        # NOTE: receipt_id is derived without identity_evidence, so the
        # evidence must be bound at make_receipt time (it is signed).
        from_s, to_s = _seed("f377l-from"), _seed("f377l-to")
        scope = "ab" * 32
        rid = di.make_receipt("alice", "mallory", scope, from_s, 100,
                              10 ** 6, None)["receipt_id"]
        alice_ctrl = _seed("f377l-alice-ctrl")
        alice_key = _seed("f377l-alice-key")
        real_doc = _did_doc("did:example:alice", alice_ctrl,
                            [_pub(alice_key)])
        mallory_ctrl = _seed("f377l-mallory-ctrl")
        forged_doc = _did_doc("did:example:alice", mallory_ctrl,
                              [_pub(from_s)])
        ev = _did_evidence(rid, "did:example:alice", forged_doc,
                           mallory_ctrl)
        rcpt = di.make_receipt("alice", "mallory", scope, from_s, 100,
                               10 ** 6, None, identity_evidence=ev)
        entries = [{"receipt": rcpt, "from_pubkey": _pub(from_s),
                    "did_documents": {"did:example:alice": forged_doc}}]
        doc = di.export_chain(entries, from_s, 200)
        try:
            rec = di.verify_chain_offline(
                doc, 200, {"did:example:alice": real_doc})
        except Exception as e:  # noqa: BLE001
            return self.assertTrue(_expect_held(
                "F377-local-override", True,
                "forged embedded doc refused coded %s"
                % getattr(e, "code", "?")) == "HELD")
        self.assertTrue(_expect_held(
            "F377-local-override", not rec.get("verified"),
            "offline verify accepted forged embedded DID doc") == "BREAK")

    def test_F377_tampered_embedded_refused(self):
        # Tampering with an embedded doc (breaking its controller
        # signature) must still refuse -- the flaw is substitution of
        # a valid self-signed doc, not acceptance of invalid
        # documents. The export path re-verifies and fails closed.
        fx = _native_chain("f377t")
        leaf = fx["chain"][-1]
        ctrl = _seed("f377t-ctrl")
        doc = _did_doc("did:example:bob", ctrl, [fx["pubs"]["mid"]])
        tampered = dict(doc)
        tampered["delegation_keys"] = [_pub(_seed("f377t-evil"))]
        ev = _did_evidence(leaf["receipt_id"], "did:example:bob",
                           doc, ctrl)  # evidence names the REAL digest
        entries = [
            {"receipt": fx["chain"][0], "identity_evidence": None,
             "did_documents": {}},
            {"receipt": leaf, "identity_evidence": ev,
             "did_documents": {"did:example:bob": tampered}},
        ]
        self.assertTrue(_expect_coded(
            "F377-tampered-embedded",
            lambda: di.export_native_chain(
                entries, fx["seeds"]["mid"], 200, 200,
                [fx["pubs"]["root"]]),
            {"delegation-identity-invalid"}) == "HELD")

    def test_F377_honest_pinned_flow_works(self):
        # The honest flow (evidence consistent with the pinned root)
        # must verify -- the fix must not break legitimate use.
        fx = _native_chain("f377h")
        leaf = fx["chain"][-1]
        ctrl = _seed("f377h-ctrl")
        doc = _did_doc("did:example:carol", ctrl, [fx["pubs"]["mid"]])
        ev = _did_evidence(leaf["receipt_id"], "did:example:carol",
                           doc, ctrl)
        entries = [
            {"receipt": fx["chain"][0], "identity_evidence": None,
             "did_documents": {}},
            {"receipt": leaf, "identity_evidence": ev,
             "did_documents": {"did:example:carol": doc}},
        ]
        chain_doc = di.export_native_chain(entries, fx["seeds"]["mid"],
                                           200, 200, [fx["pubs"]["root"]])
        rec = di.verify_native_chain_offline(
            chain_doc, 200, {"did:example:carol": doc},
            [fx["pubs"]["root"]])
        self.assertTrue(_expect_held(
            "F377-honest-flow", rec.get("verified") is True,
            "honest pinned flow must verify") == "HELD")


# ------------------------------------------------------------------
# F378: ticket presentation ignores revocation
# ------------------------------------------------------------------

class F378TicketRevocationTest(unittest.TestCase):
    """F378 (MEDIUM, CLOSED 2026-10-03 wave-301 lane 2): a delegation
    ticket anchored on a receipt (``issue_ticket_on_receipt``) kept
    presenting successfully AFTER the anchoring receipt was revoked --
    ``present()`` took no revocation input at all.  Wave-301 re-pin:
    both paths now take ``revocation={"revoker": DelegationRevoker}``
    and enforce revocation liveness fail-closed (wave-300 lane-4
    precedent): no revocation state -> coded
    ``delegation-ticket-invalid``; revoked anchor/ancestor -> coded
    ``delegation-revoked``; a substituted revoker (wrong delegator or
    wrong key) -> coded ``delegation-ticket-invalid``.  Pure ticket
    chains still present without revocation input."""

    def _ticket_on_receipt(self, tag="f378"):
        # The ticket issuer must HOLD the anchoring receipt: the leaf
        # holder's seed issues the ticket.  The anchor's delegator
        # ("mid-<tag>") owns the revocation list presented at issue
        # and at presentation.
        fx = _native_chain(tag)
        chain = fx["chain"]
        leaf = chain[-1]
        delegatee = _seed(tag + "-delegatee")
        opt = tkt.declare_opt_in(delegatee, "d-" + tag, 10 ** 6, 100)
        reg = tkt.OptInRegistry()
        reg.register(opt, 100)
        revoker = rv.DelegationRevoker(fx["seeds"]["mid"], "mid-" + tag)
        revocation = {"revoker": revoker}
        ticket, ticket_seed = tkt.issue_ticket_on_receipt(
            leaf, chain, fx["seeds"]["leaf"], "d-" + tag, "memory.read",
            tkt.FORWARDABLE, [], 10 ** 6, reg, 100,
            [fx["pubs"]["root"]], revocation=revocation)
        return fx, chain, leaf, ticket, ticket_seed, delegatee, revocation

    def _present(self, ticket, tag, at, chain, pubs, revocation):
        return tkt.present(ticket, "d-" + tag, "memory.read", "ab" * 32,
                           at, receipt_chain=chain,
                           trust_roots=[pubs["root"]],
                           revocation=revocation)

    def test_F378_present_after_receipt_revoked(self):
        fx, chain, leaf, ticket, ticket_seed, delegatee, revocation = \
            self._ticket_on_receipt()
        # The ticket presents fine before revocation.
        got = self._present(ticket, "f378", 200, chain, fx["pubs"],
                            revocation)
        assert got is not None
        # Now the delegator revokes the anchoring receipt.
        revocation["revoker"].revoke(leaf["receipt_id"], 300)
        try:
            self._present(ticket, "f378", 400, chain, fx["pubs"],
                          revocation)
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
            return self.assertTrue(_expect_held(
                "F378-present-after-revoke", code == "delegation-revoked",
                "post-revoke presentation refused coded %s" % (code,))
                == "HELD")
        self.assertTrue(_expect_held(
            "F378-present-after-revoke", False,
            "ticket anchored on a REVOKED receipt still presents") == "BREAK")

    def test_F378_issue_on_already_revoked_receipt(self):
        # Issuance on an already-revoked receipt refuses coded: the
        # issue path now enforces revocation liveness fail-closed.
        # (The ticket issuer must HOLD the anchoring receipt, so the
        # leaf holder's seed issues here.)
        fx = _native_chain("f378i")
        chain, leaf = fx["chain"], fx["chain"][-1]
        revoker = rv.DelegationRevoker(fx["seeds"]["mid"], "mid-f378i")
        revoker.revoke(leaf["receipt_id"], 150)
        delegatee = _seed("f378i-delegatee")
        opt = tkt.declare_opt_in(delegatee, "d-f378i", 10 ** 6, 100)
        reg = tkt.OptInRegistry()
        reg.register(opt, 100)
        try:
            tkt.issue_ticket_on_receipt(
                leaf, chain, fx["seeds"]["leaf"], "d-f378i",
                "memory.read", tkt.FORWARDABLE, [], 10 ** 6, reg, 200,
                [fx["pubs"]["root"]],
                revocation={"revoker": revoker})
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
            return self.assertTrue(_expect_held(
                "F378-issue-on-revoked", code == "delegation-revoked",
                "issuance on revoked receipt refused coded %s" % (code,))
                == "HELD")
        self.assertTrue(_expect_held(
            "F378-issue-on-revoked", False,
            "ticket issued on an already-REVOKED receipt") == "BREAK")

    def test_F378_present_without_revocation_state_fail_closed(self):
        # No revocation state on a receipt-anchored presentation
        # refuses coded -- the kill switch is not optional.
        fx, chain, leaf, ticket, ticket_seed, delegatee, revocation = \
            self._ticket_on_receipt()
        self.assertTrue(_expect_coded(
            "F378-present-no-revocation-state",
            lambda: tkt.present(ticket, "d-f378", "memory.read",
                                "ab" * 32, 200, receipt_chain=chain,
                                trust_roots=[fx["pubs"]["root"]]),
            {"delegation-ticket-invalid"}) == "HELD")

    def test_F378_issue_without_revocation_state_fail_closed(self):
        fx = _native_chain("f378j")
        chain, leaf = fx["chain"], fx["chain"][-1]
        delegatee = _seed("f378j-delegatee")
        opt = tkt.declare_opt_in(delegatee, "d-f378j", 10 ** 6, 100)
        reg = tkt.OptInRegistry()
        reg.register(opt, 100)
        self.assertTrue(_expect_coded(
            "F378-issue-no-revocation-state",
            lambda: tkt.issue_ticket_on_receipt(
                leaf, chain, fx["seeds"]["leaf"], "d-f378j",
                "memory.read", tkt.FORWARDABLE, [], 10 ** 6, reg, 200,
                [fx["pubs"]["root"]]),
            {"delegation-ticket-invalid"}) == "HELD")

    def test_F378_substituted_revoker_refused(self):
        # An attacker's own revoker (wrong delegator id AND wrong key)
        # must not silently validate: anti-substitution binds the
        # revoker to the anchoring receipt's delegator key.
        fx, chain, leaf, ticket, ticket_seed, delegatee, revocation = \
            self._ticket_on_receipt()
        evil = rv.DelegationRevoker(_seed("f378-evil"), "evil-f378")
        self.assertTrue(_expect_coded(
            "F378-substituted-revoker",
            lambda: self._present(ticket, "f378", 200, chain, fx["pubs"],
                                  {"revoker": evil}),
            {"delegation-ticket-invalid"}) == "HELD")
        # Right id, wrong key: also refused.
        evil2 = rv.DelegationRevoker(_seed("f378-evil2"), "mid-f378")
        self.assertTrue(_expect_coded(
            "F378-substituted-revoker-key",
            lambda: self._present(ticket, "f378", 200, chain, fx["pubs"],
                                  {"revoker": evil2}),
            {"delegation-ticket-invalid"}) == "HELD")

    def test_F378_ancestor_revocation_kills_ticket(self):
        # Revoking an ANCESTOR of the anchor kills the ticket too:
        # assert_live_native checks every chain member.
        fx, chain, leaf, ticket, ticket_seed, delegatee, revocation = \
            self._ticket_on_receipt()
        revocation["revoker"].revoke(chain[0]["receipt_id"], 150)
        self.assertTrue(_expect_coded(
            "F378-ancestor-revoked",
            lambda: self._present(ticket, "f378", 200, chain,
                                  fx["pubs"], revocation),
            {"delegation-revoked"}) == "HELD")

    def test_F378_native_revocation_still_enforced(self):
        # Control: the receipt-layer revocation path itself works --
        # the gap was ticket presentation, not revocation per se.
        fx = _native_chain("f378c")
        chain, leaf = fx["chain"], fx["chain"][-1]
        revoker = rv.DelegationRevoker(fx["seeds"]["mid"], "mid-f378c")
        revoker.revoke(leaf["receipt_id"], 300)
        self.assertTrue(_expect_coded(
            "F378-native-revoke-enforced",
            lambda: revoker.assert_live_native(
                chain, 400, [fx["pubs"]["root"]]),
            {"delegation-revoked"}) == "HELD")


# ------------------------------------------------------------------
# A. Receipt-shape adapter confusion
# ------------------------------------------------------------------

class AdapterConfusionTest(unittest.TestCase):
    """Target A: the wave-299 merge kept lane 2's native shape
    canonical and added native-aware paths (no field-translating
    adapters). Cross-shape inputs must refuse coded, never silently
    validate."""

    def test_A_local_shape_into_assert_live_native(self):
        # A local-shape (revocation-lane) receipt fed to the native
        # path must refuse coded -- not validate, not crash uncoded.
        revoker = rv.DelegationRevoker(_seed("a1"), "a1")
        local = {
            "schema": "delegation-receipt/v1",
            "receipt_id": "ab" * 32,
            "delegator_id": "a1", "delegate_id": "b1",
            "parent_receipt_id": None, "epoch": 0,
            "capabilities": ["memory.read"],
            "not_before": 100, "not_after": 10 ** 6,
            "signature": "cd" * 64,
        }
        self.assertTrue(_expect_coded(
            "A-local-into-native",
            lambda: revoker.assert_live_native(
                [local], 200, [_pub(_seed("a1-root"))]),
            {"delegation-invalid", "delegation-chain-broken",
             "delegation-revocation-invalid"}) == "HELD")

    def test_A_native_into_local_is_live(self):
        # A native receipt fed to the local-shape is_live must refuse
        # coded -- the shapes are not interchangeable.
        fx = _native_chain("a2")
        revoker = rv.DelegationRevoker(_seed("a2"), "mid-a2")
        self.assertTrue(_expect_coded(
            "A-native-into-local",
            lambda: revoker.is_live(
                [dict(r) for r in fx["chain"]], 200,
                {"mid-a2": fx["pubs"]["mid"]}),
            {"delegation-revocation-invalid"}) == "HELD")

    def test_A_revoke_native_id_then_assert(self):
        # Revocation is shape-agnostic on receipt ids: revoking a
        # native receipt id kills its native chain presentation.
        fx = _native_chain("a3")
        chain, leaf = fx["chain"], fx["chain"][-1]
        revoker = rv.DelegationRevoker(fx["seeds"]["mid"], "mid-a3")
        revoker.revoke(leaf["receipt_id"], 300)
        self.assertTrue(_expect_coded(
            "A-revoke-native-id",
            lambda: revoker.assert_live_native(
                chain, 400, [fx["pubs"]["root"]]),
            {"delegation-revoked"}) == "HELD")


# ------------------------------------------------------------------
# C. Capability manifests
# ------------------------------------------------------------------

def _sup_with_endowment(tag, endowment, specs):
    return sup.Supervisor("sup-" + tag, specs, _seed(tag + "-sup"),
                          endowment=endowment)


class CapabilityManifestTest(unittest.TestCase):
    """Target C: gov/supervision.py capability manifests."""

    def test_C_endowment_unknown_child_refused(self):
        # An endowment claiming rights from a child that was never
        # declared must refuse at supervisor construction.
        spec = sup.ChildSpec("c1", _pub(_seed("c1k")), "one_for_one",
                             3, 3600)
        def build():
            _sup_with_endowment(
                "c-end", {"db": {"rights": {"r"}, "held": "use",
                                        "from": "ghost-child"}}, [spec])
        self.assertTrue(_expect_coded(
            "C-endowment-unknown-child", build,
            {"supervision-undeclared-child"}) == "HELD")

    def test_C_exercise_routed_refused(self):
        # exercise() on a merely-routed capability refuses even when
        # the claimed rights are within the routed set.
        spec = sup.ChildSpec("c1", _pub(_seed("c1k")), "one_for_one",
                             3, 3600)
        s = _sup_with_endowment(
            "c-ex", {"db": {"rights": {"r", "w"}, "held": "route",
                            "from": "parent"}}, [spec])
        self.assertTrue(_expect_coded(
            "C-exercise-routed",
            lambda: s.exercise("db", {"r"}),
            {"supervision-capability-route-violation"}) == "HELD")

    def test_C_exercise_undeclared_refused(self):
        spec = sup.ChildSpec("c1", _pub(_seed("c1k")), "one_for_one",
                             3, 3600)
        s = _sup_with_endowment("c-ex2", None, [spec])
        self.assertTrue(_expect_coded(
            "C-exercise-undeclared",
            lambda: s.exercise("db", {"r"}),
            {"supervision-capability-undeclared"}) == "HELD")

    def test_C_manifest_copy_mutation_holds(self):
        # The manifest property returns a deep copy: mutating it must
        # not change the frozen grant.
        spec = sup.ChildSpec(
            "c1", _pub(_seed("c1k")), "one_for_one", 3, 3600,
            capabilities={
                "use": [{"capability": "db", "rights": {"r"},
                         "from": "self"}],
                "offer": [], "expose": []})
        s = _sup_with_endowment("c-copy", None, [spec])
        before = s.granted_capabilities("c1")
        copy = spec.manifest
        copy["use"][0]["rights"].append("w")
        copy["use"].append({"capability": "db2", "rights": ["r"],
                            "from": "self"})
        after = s.granted_capabilities("c1")
        self.assertTrue(_expect_held(
            "C-manifest-copy", before == after == {"db": ["r"]},
            "grant changed via manifest copy: %r -> %r" % (before, after))
            == "HELD")

    def test_C_expose_offer_cycle_no_widening(self):
        # Expose->offer-back-to-the-same-child: each step is
        # attenuation-checked, so rights cannot widen through the
        # cycle. The grant must equal the declared rights exactly.
        spec = sup.ChildSpec(
            "a", _pub(_seed("cyc-k")), "one_for_one", 3, 3600,
            capabilities={
                "expose": [{"capability": "log", "rights": {"r"},
                            "from": "self"}],
                "use": [{"capability": "log", "rights": {"r"},
                         "from": "parent"}],
                "offer": [],
            })
        s = _sup_with_endowment(
            "c-cyc",
            {"log": {"rights": {"r"}, "held": "use", "from": "a"}},
            [spec])
        grant = s.granted_capabilities("a")
        routing = s.exposed_routing()
        ok = (grant == {"log": ["r"]}
              and routing["a"]["log"]["status"] == "routed")
        self.assertTrue(_expect_held(
            "C-expose-cycle", ok,
            "grant=%r routing=%r" % (grant, routing)) == "HELD")

    def test_C_offer_wider_than_use_refused(self):
        # A child may only offer what its use entries hold: offering
        # wider rights than held refuses at declaration.
        def build():
            spec = sup.ChildSpec(
                "a", _pub(_seed("cyc2-k")), "one_for_one", 3, 3600,
                capabilities={
                    "use": [{"capability": "log", "rights": {"r"},
                             "from": "self"}],
                    "offer": [{"capability": "log", "rights": {"r", "w"},
                               "from": "self"}],
                    "expose": [],
                })
            _sup_with_endowment("c-wide", None, [spec])
        self.assertTrue(_expect_coded(
            "C-offer-wider", build,
            {"supervision-capability-rights-exceeded"}) == "HELD")


# ------------------------------------------------------------------
# D. Identity evidence chains
# ------------------------------------------------------------------

class IdentityChainTest(unittest.TestCase):
    """Target D: identity evidence chain properties."""

    def _transcript(self, tag, generator_seed, witnesses):
        return di.make_ceremony_transcript(
            "gen-" + tag, generator_seed, 100, "tpm2-hardware",
            [("wit-" + w, _seed(tag + "-wit-" + w)) for w in witnesses])

    def test_D_witness_coverage_enforced(self):
        # witnessed_by names a witness with no signature: refused.
        # (Hand-built: the body declares wit-b, but only wit-a signs --
        # the signature domain is the body without witness_signatures.)
        gen = _seed("d-wit")
        ws_a = _seed("d-wit-wit-a")
        body = {"generated_by": "gen-d-wit",
                "generator_pubkey": _pub(gen),
                "generated_at": 100, "host_class": "tpm2-hardware",
                "witnessed_by": ["wit-a", "wit-b"]}
        t = dict(body)
        t["witness_signatures"] = [
            {"witness": "wit-a", "pubkey": _pub(ws_a),
             "signature": _ed25519.sign(ws_a, _canon(body)).hex()}]
        fx = _native_chain("d-wit")
        leaf = fx["chain"][-1]
        # Coverage is enforced at evidence-build time: the uncovered
        # witness set cannot even be packaged.
        self.assertTrue(_expect_coded(
            "D-witness-coverage",
            lambda: di.make_identity_evidence(
                "attestation", leaf["receipt_id"],
                ceremony_transcript=t, claim_hardware=False),
            {"delegation-identity-invalid"}) == "HELD")

    def test_D_quote_bytes_shape_only(self):
        # Documented behavior: quote_bytes is shape-checked (must be a
        # string when present), not content-verified -- deployment
        # verifies real TPM quotes against its roots. A garbage
        # string passes the shape check (falsified-not-filed as a
        # break; pinned here as documented). The transcript generator
        # must be the receipt signer (mid).
        fx = _native_chain("d-q")
        t = self._transcript("d-q", fx["seeds"]["mid"], ["a"])
        leaf = fx["chain"][-1]
        ev = di.make_identity_evidence(
            "attestation", leaf["receipt_id"],
            ceremony_transcript=t, claim_hardware=True,
            quote_bytes="not-a-real-quote")
        rec = di.verify_identity_evidence(ev, leaf["receipt_id"],
                                          fx["pubs"]["mid"], {})
        self.assertTrue(_expect_held(
            "D-quote-shape", rec.get("label") == "hardware-attested",
            "shape-only quote check is the documented contract") == "HELD")

    def test_D_hardware_claim_without_quote_refused(self):
        # claim_hardware=True with NO quote bytes refuses loud.
        gen = _seed("d-hw")
        t = self._transcript("d-hw", gen, ["a"])
        fx = _native_chain("d-hw")
        leaf = fx["chain"][-1]
        self.assertTrue(_expect_coded(
            "D-hw-no-quote",
            lambda: di.make_identity_evidence(
                "attestation", leaf["receipt_id"],
                ceremony_transcript=t, claim_hardware=True),
            {"delegation-identity-false-hardware-claim"}) == "HELD")

    def test_D_per_link_did_independence(self):
        # Each link's evidence is verified independently against the
        # roots: different links may carry different DIDs (different
        # signers). This is by design, not a substitution break.
        fx = _native_chain("d-per")
        chain = fx["chain"]
        ctrl1, ctrl2 = _seed("d-per-c1"), _seed("d-per-c2")
        doc1 = _did_doc("did:example:one", ctrl1, [fx["pubs"]["root"]])
        doc2 = _did_doc("did:example:two", ctrl2, [fx["pubs"]["mid"]])
        ev1 = _did_evidence(chain[0]["receipt_id"], "did:example:one",
                            doc1, ctrl1)
        ev2 = _did_evidence(chain[1]["receipt_id"], "did:example:two",
                            doc2, ctrl2)
        entries = [
            {"receipt": chain[0], "identity_evidence": ev1,
             "did_documents": {"did:example:one": doc1}},
            {"receipt": chain[1], "identity_evidence": ev2,
             "did_documents": {"did:example:two": doc2}},
        ]
        doc = di.export_native_chain(entries, fx["seeds"]["mid"], 200,
                                     200, [fx["pubs"]["root"]])
        rec = di.verify_native_chain_offline(
            doc, 200,
            {"did:example:one": doc1, "did:example:two": doc2},
            [fx["pubs"]["root"]])
        self.assertTrue(_expect_held(
            "D-per-link-did", rec.get("verified") is True,
            "per-link DID independence is by design") == "HELD")


# ------------------------------------------------------------------
# E. F374 / F375 / F376 re-verification (BREAK-iff-vulnerable:
#    flips HELD on the merged tree with lanes 1-2 closures landed)
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


def _rc_candidate(owner_seed, namespace, key, value_digest, op,
                  principal, written_at=100, supersedes=None,
                  expires_at=None):
    cand = {"schema": "memory-record/v1", "namespace": namespace,
            "key": key, "value_digest": value_digest,
            "written_at": written_at, "supersedes": supersedes,
            "provenance": {"source_principal": principal,
                           "reliability": "C1", "corroborations": 0,
                           "ingested_at": written_at},
            "expires_at": expires_at, "op": op}
    unsigned = {k: cand[k] for k in
                ("schema", "namespace", "key", "value_digest",
                 "written_at", "supersedes", "provenance",
                 "expires_at", "op") if k in cand}
    cand["signature"] = _ed25519.sign(owner_seed,
                                      _canon(unsigned)).hex()
    return cand


class F374F375F376ReverifyTest(unittest.TestCase):
    """Target E: F374/F375/F376 were OPEN when this battery was
    written (lanes 1-2 closed them in parallel). The probes are
    BREAK-iff-vulnerable: they flip HELD against the wave-300 merged
    tree with the closures landed."""

    def test_F374_hostile_tombstone(self):
        victim, attacker = _seed("e-vic"), _seed("e-atk")
        ms = mst.MemoryStore()
        ep_v = _ms_episode(ms, victim, "vic", 100)
        _ms_fact(ms, victim, "vic", ep_v, "k1", "cd" * 32, 100, 100)
        ep_a = _ms_episode(ms, attacker, "atk", 200, digest="ef" * 32)
        _ms_fact(ms, attacker, "atk", ep_a, "k1", "12" * 32, 200, 200,
                 reliability="D", credibility=4)
        try:
            _ms_retract(ms, attacker, "atk", "k1", 300)
        except mst.MemoryStoreError as e:
            return self.assertTrue(_expect_held(
                "F374-hostile-tombstone", True,
                "hostile retract refused coded %s" % (e.code,)) == "HELD")
        # Retract landed: the victim re-records and tries to recall.
        # The key is permanently dead -- this is the filed F374 break,
        # so the probe records BREAK when the break reproduces.
        ep_v2 = _ms_episode(ms, victim, "vic", 400, digest="aa" * 32)
        _ms_fact(ms, victim, "vic", ep_v2, "k1", "bb" * 32, 400, 400)
        try:
            ms.recall("k1", 500)
        except mst.MemoryStoreError as e:
            _record("F374-hostile-tombstone", "BREAK",
                    "victim's key permanently dead after hostile retract "
                    "(coded %s)" % (e.code,))
        else:
            _record("F374-hostile-tombstone", "BREAK",
                    "hostile retract had no effect -- finding not "
                    "reproduced")
        self.assertTrue(True)

    def test_F375_rate_bound_rotation(self):
        owner = _seed("e-own")
        rc = mrc.MemoryReconciler(owner, "rc-e",
                                  max_writes_per_principal=2,
                                  write_window_seconds=3600)
        rc.declare_namespace("alice", _pub(owner))
        # Same principal string 3x: the 3rd must refuse.
        for i in range(2):
            c = _rc_candidate(owner, "alice", "k%d" % i, "ab" * 32,
                              "add", "writer", written_at=100 + i)
            rc.reconcile(c, [], {}, 100 + i)
        c3 = _rc_candidate(owner, "alice", "k9", "ab" * 32, "add",
                           "writer", written_at=102)
        refused = False
        try:
            rc.reconcile(c3, [], {}, 102)
        except mrc.MemoryReconcileError:
            refused = True
        # Rotating the self-reported principal string evades the bound.
        rc2 = mrc.MemoryReconciler(owner, "rc-e2",
                                   max_writes_per_principal=2,
                                   write_window_seconds=3600)
        rc2.declare_namespace("alice", _pub(owner))
        accepted = 0
        for i in range(6):
            c = _rc_candidate(owner, "alice", "k%d" % i, "ab" * 32,
                              "add", "writer-%d" % i, written_at=100 + i)
            try:
                rc2.reconcile(c, [], {}, 100 + i)
                accepted += 1
            except mrc.MemoryReconcileError:
                pass
        broke = (refused and accepted == 6)
        self.assertTrue(_expect_held(
            "F375-rate-rotation", not broke,
            "control refused=%s rotated accepted %d/6"
            % (refused, accepted)) == ("BREAK" if broke else "HELD"))

    def test_F376_caller_namespace_assertion(self):
        owner = _seed("e-own2")
        rc = mrc.MemoryReconciler(owner, "rc-e3")
        rc.declare_namespace("alice", _pub(owner))
        rc.declare_namespace("bob", _pub(_seed("e-bob")))
        c = _rc_candidate(owner, "alice", "secret", "ab" * 32, "add",
                          "alice-writer", written_at=100)
        rc.reconcile(c, [], {}, 100)
        # Live alice->bob grant exists; an UNAUTHENTICATED caller
        # asserting "bob" reads alice's fact.
        rc.grant_sharing("alice", "bob", 100, 10 ** 6, owner)
        try:
            rec = rc.recall({"namespace": "alice", "key": "secret"},
                            "bob", 200)
        except mrc.MemoryReconcileError as e:
            return self.assertTrue(_expect_held(
                "F376-caller-assertion", True,
                "self-asserted caller refused coded %s"
                % (e.code,)) == "HELD")
        self.assertTrue(_expect_held(
            "F376-caller-assertion", rec is None,
            "unauthenticated caller asserting 'bob' read alice's fact")
            == "BREAK")


# ------------------------------------------------------------------
# Re-pins of prior red-team batteries
# ------------------------------------------------------------------

class RepinTest(unittest.TestCase):
    def test_repin_w299_redteam(self):
        # Wave-300 merge re-pin: F374/F375/F376 CLOSED by lanes 1-2
        # (their probes flip HELD, incl. lane 1's two new F374 probes);
        # footer-state probes re-pinned to the merged footer.
        # Expect 0 BREAK / 39 HELD.
        import subprocess
        tmp = "/var/tmp/g300-repin-%d" % os.getpid()
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        path = os.path.join(REPO, "evals", "w299_redteam_probes.py")
        out = subprocess.run([sys.executable, path], capture_output=True,
                             text=True, env=env, timeout=600)
        line = (out.stdout.strip().splitlines() or [""])[0]
        ok = ("0 BREAK / 39 HELD" in out.stdout)
        self.assertTrue(_expect_held(
            "repin-w299-redteam", ok, line) == "HELD")

    def test_repin_w298_redteam(self):
        # Wave-300 merge re-pin: footer-state probe re-pinned to the
        # merged footer. Expect 0 BREAK / 22 HELD.
        import subprocess
        tmp = "/var/tmp/g300-repin-%d" % os.getpid()
        os.makedirs(tmp, exist_ok=True)
        env = dict(os.environ, GOV_SKIP_GREEN="1", TMPDIR=tmp)
        path = os.path.join(REPO, "evals", "w298_redteam_probes.py")
        out = subprocess.run([sys.executable, path], capture_output=True,
                             text=True, env=env, timeout=600)
        line = (out.stdout.strip().splitlines() or [""])[0]
        ok = ("0 BREAK / 22 HELD" in out.stdout)
        self.assertTrue(_expect_held(
            "repin-w298-redteam", ok, line) == "HELD")


# ------------------------------------------------------------------
# Depth-1 green checks
# ------------------------------------------------------------------

def _green_check(battery, expect):
    env = dict(os.environ, GOV_SKIP_GREEN="1")
    tmp = "/var/tmp/g300-green-%s" % os.getpid()
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
    if expect in out.stdout:
        return ("HELD", summary)
    return ("BREAK", summary)


class GreenCheckTest(unittest.TestCase):
    def test_green_w299_redteam(self):
        if os.environ.get("GOV_SKIP_GREEN"):
            _record("green-w299-redteam", "HELD", "skipped (depth-1)")
            return
        # Wave-300 merge re-pin: 0 BREAK / 39 HELD (see RepinTest).
        status, detail = _green_check("w299_redteam_probes.py",
                                      "0 BREAK / 39 HELD")
        self.assertTrue(_expect_held(
            "green-w299-redteam", status == "HELD", detail) == "HELD")

    def test_green_w298_redteam(self):
        if os.environ.get("GOV_SKIP_GREEN"):
            _record("green-w298-redteam", "HELD", "skipped (depth-1)")
            return
        # Wave-300 merge re-pin: 0 BREAK / 22 HELD (see RepinTest).
        status, detail = _green_check("w298_redteam_probes.py",
                                      "0 BREAK / 22 HELD")
        self.assertTrue(_expect_held(
            "green-w298-redteam", status == "HELD", detail) == "HELD")


def main():
    global _results
    _results = []
    suite = unittest.TestSuite()
    loader = unittest.TestLoader()
    for cls in (BaseStateTest, F377DIDTrustRootTest,
                F378TicketRevocationTest, AdapterConfusionTest,
                CapabilityManifestTest, IdentityChainTest,
                F374F375F376ReverifyTest, RepinTest, GreenCheckTest):
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
