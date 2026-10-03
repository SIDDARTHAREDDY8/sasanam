"""Unit tests for the wave-299 Kerberos-style delegation ticket model.

Every coded refusal is asserted by code; the ed25519 verify contract
(is True / is False, wave-243) is pinned.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation_tickets as dt
from gov import ed25519


def _seed(tag):
    return hashlib.sha256(("w299-test-delegation-tickets-%s" % tag)
                          .encode()).digest()


AT = 3000000


def _registry(at=AT):
    reg = dt.OptInRegistry()
    reg.register(dt.declare_opt_in(_seed("a1"), "agent-1", 3600, at), at)
    reg.register(dt.declare_opt_in(_seed("a2"), "agent-2", 3600, at), at)
    return reg


def _chain(at=AT):
    reg = _registry(at)
    root, root_seed = dt.issue_root_ticket(_seed("auth"), "authority",
                                           "sasanam.tools", 7200, at)
    t1, t1_seed = dt.issue_delegation_ticket(
        root, root_seed, "agent-1", "sasanam.tools.read",
        dt.FORWARDABLE, None, 3600, reg, at)
    return reg, root, root_seed, t1, t1_seed


class OptInTests(unittest.TestCase):
    def test_declare_and_register(self):
        reg = dt.OptInRegistry()
        opt = dt.declare_opt_in(_seed("a1"), "agent-1", 3600, AT)
        self.assertTrue(reg.register(opt, AT))
        self.assertTrue(reg.is_opted_in("agent-1", AT))

    def test_not_opted_in_unknown(self):
        reg = dt.OptInRegistry()
        self.assertFalse(reg.is_opted_in("nobody", AT))

    def test_opt_in_expires(self):
        reg = dt.OptInRegistry()
        reg.register(dt.declare_opt_in(_seed("a1"), "agent-1", 3600, AT),
                     AT)
        self.assertFalse(reg.is_opted_in("agent-1", AT + 3600))

    def test_forged_opt_in_refused(self):
        reg = dt.OptInRegistry()
        opt = dict(dt.declare_opt_in(_seed("a1"), "agent-1", 3600, AT))
        opt["principal_id"] = "agent-2"
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            reg.register(opt, AT)
        self.assertEqual(ctx.exception.code,
                         "delegation-ticket-invalid")

    def test_opt_in_ttl_bounds(self):
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.declare_opt_in(_seed("a1"), "agent-1", 10, AT)
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")


class IssuanceTests(unittest.TestCase):
    def test_root_ticket_shape(self):
        root, _ = dt.issue_root_ticket(_seed("auth"), "authority",
                                       "sasanam.tools", 7200, AT)
        self.assertEqual(root["parent_ticket_digest"],
                         dt.ROOT_PARENT_DIGEST)
        self.assertEqual(root["delegatee_id"], "authority")

    def test_forwardable_delegation(self):
        _, _, _, t1, _ = _chain()
        self.assertEqual(t1["ticket_type"], dt.FORWARDABLE)
        self.assertEqual(t1["delegatee_id"], "agent-1")

    def test_ticket_key_fresh_per_ticket(self):
        _, root, _, t1, _ = _chain()
        self.assertNotEqual(t1["ticket_key_pub"], root["ticket_key_pub"])

    def test_tickets_frozen(self):
        _, _, _, t1, _ = _chain()
        with self.assertRaises(TypeError):
            t1["scope"] = "sasanam.admin"

    def test_self_delegation_refused(self):
        reg, root, root_seed, _, _ = _chain()
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.issue_delegation_ticket(
                root, root_seed, "authority", "sasanam.tools",
                dt.FORWARDABLE, None, 600, reg, AT)
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")

    def test_constrained_empty_downstream(self):
        reg, _, _, t1, t1_seed = _chain()
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.issue_delegation_ticket(
                t1, t1_seed, "agent-2", "sasanam.tools.read",
                dt.CONSTRAINED, [], 600, reg, AT)
        self.assertEqual(ctx.exception.code,
                         "delegation-ticket-type-violated")

    def test_non_forwardable_cannot_redelegate(self):
        reg, _, _, t1, t1_seed = _chain()
        tnf, tnf_seed = dt.issue_delegation_ticket(
            t1, t1_seed, "agent-2", "sasanam.tools.read",
            dt.NON_FORWARDABLE, None, 600, reg, AT)
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.issue_delegation_ticket(
                tnf, tnf_seed, "agent-1", "sasanam.tools.read",
                dt.FORWARDABLE, None, 300, reg, AT)
        self.assertEqual(ctx.exception.code,
                         "delegation-ticket-type-violated")


class PresentationTests(unittest.TestCase):
    def test_present_happy_path(self):
        _, root, _, t1, t1_seed = _chain()
        store = {t1["parent_ticket_digest"]: root}
        act = hashlib.sha256(b"x").hexdigest()
        sig = dt.attest_action(t1_seed, t1, act)
        out = dt.present(t1, "agent-1", "sasanam.tools.read.db", act,
                         AT + 5, store, sig)
        self.assertEqual(out["ticket_id"], t1["ticket_id"])

    def test_present_without_attestation(self):
        _, root, _, t1, _ = _chain()
        store = {t1["parent_ticket_digest"]: root}
        act = hashlib.sha256(b"x").hexdigest()
        out = dt.present(t1, "agent-1", "sasanam.tools.read", act,
                         AT + 5, store, None)
        self.assertEqual(out["ticket_id"], t1["ticket_id"])

    def test_ticket_key_confusion(self):
        reg, root, root_seed, t1, t1_seed = _chain()
        tc, _ = dt.issue_delegation_ticket(
            t1, t1_seed, "agent-2", "sasanam.tools.read",
            dt.FORWARDABLE, None, 600, reg, AT)
        store = {t1["parent_ticket_digest"]: root,
                 tc["parent_ticket_digest"]: t1}
        act = hashlib.sha256(b"x").hexdigest()
        bad = ed25519.sign(t1_seed, bytes.fromhex(act)).hex()
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.present(tc, "agent-2", "sasanam.tools.read", act,
                       AT + 5, store, bad)
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")

    def test_chain_depth_bound(self):
        import json
        reg = _registry()
        root, root_seed = dt.issue_root_ticket(_seed("auth"), "authority",
                                               "s", 7200, AT)
        parent, pkey = root, root_seed
        tickets = [root]
        for i in range(33):
            who = "agent-%d" % (i % 2 + 1)
            nxt, nkey = dt.issue_delegation_ticket(
                parent, pkey, who, "s", dt.FORWARDABLE, None, 60,
                reg, AT)
            tickets.append(nxt)
            parent, pkey = nxt, nkey

        def _pdigest(t):
            return hashlib.sha256(
                json.dumps({k: t[k] for k in dt._TICKET_FIELDS},
                           sort_keys=True,
                           separators=(",", ":")).encode()).hexdigest()

        by_digest = {_pdigest(t): t for t in tickets}
        pd_store = {t["parent_ticket_digest"]: by_digest[
            t["parent_ticket_digest"]] for t in tickets[1:]}
        deepest = tickets[-1]
        act = hashlib.sha256(b"x").hexdigest()
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.present(deepest, deepest["delegatee_id"], "s", act,
                       AT + 5, pd_store, None)
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")


class Ed25519ContractTests(unittest.TestCase):
    def test_verify_contract(self):
        seed = _seed("contract")
        pub = ed25519.publickey(seed)
        msg = b"contract-msg"
        sig = ed25519.sign(seed, msg)
        self.assertIs(ed25519.verify(pub, msg, sig), True)
        bad = bytearray(sig)
        bad[7] ^= 1
        self.assertIs(ed25519.verify(pub, msg, bytes(bad)), False)


class TicketRevocationTests(unittest.TestCase):
    """Wave-301 F378: receipt-anchored tickets enforce revocation
    liveness fail-closed. Every coded refusal asserted by code."""

    def _receipt_ticket(self, tag="f378u"):
        from gov import delegation as dg
        from gov import delegation_revocation as dr
        rs = _seed(tag + "-root")
        ms = _seed(tag + "-mid")
        ls = _seed(tag + "-leaf")
        pubs = {k: ed25519.publickey(s).hex()
                for k, s in (("r", rs), ("m", ms), ("l", ls))}
        cons = {"expires_at": AT + 10 ** 6, "max_depth": 8}
        root = dg.issue(rs, "rt-" + tag, "mid-" + tag, pubs["m"],
                        {"memory.read"}, constraints=dict(cons))
        mid = dg.issue(ms, "mid-" + tag, "leaf-" + tag, pubs["l"],
                       {"memory.read"}, parent=root,
                       constraints=dict(cons))
        chain = [root, mid]
        reg = _registry()
        revoker = dr.DelegationRevoker(ms, "mid-" + tag)
        revocation = {"revoker": revoker}
        ticket, _ = dt.issue_ticket_on_receipt(
            mid, chain, ls, "agent-1", "memory.read",
            dt.FORWARDABLE, [], 3600, reg, AT, [pubs["r"]],
            revocation=revocation)
        act = hashlib.sha256(b"u").hexdigest()
        return {"chain": chain, "ticket": ticket, "act": act,
                "roots": [pubs["r"]], "revocation": revocation,
                "revoker": revoker, "mid_id": mid["receipt_id"]}

    def _present(self, fx, at, revocation):
        return dt.present(fx["ticket"], "agent-1", "memory.read",
                          fx["act"], at, receipt_chain=fx["chain"],
                          trust_roots=fx["roots"], revocation=revocation)

    def test_present_live_receipt_with_revocation_ok(self):
        fx = self._receipt_ticket()
        out = self._present(fx, AT + 5, fx["revocation"])
        self.assertEqual(out["ticket_id"], fx["ticket"]["ticket_id"])

    def test_present_without_revocation_state_fail_closed(self):
        fx = self._receipt_ticket()
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            self._present(fx, AT + 5, None)
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")

    def test_present_after_anchor_revoked(self):
        fx = self._receipt_ticket()
        fx["revoker"].revoke(fx["mid_id"], AT + 1)
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            self._present(fx, AT + 5, fx["revocation"])
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_issue_on_revoked_receipt_refused(self):
        from gov import delegation as dg
        from gov import delegation_revocation as dr
        fx = self._receipt_ticket(tag="f378ui")
        # Build a second ticket issuance attempt on the revoked anchor.
        fx["revoker"].revoke(fx["mid_id"], AT + 1)
        reg = _registry()
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            dt.issue_ticket_on_receipt(
                fx["chain"][-1], fx["chain"],
                _seed("f378ui-leaf"), "agent-2", "memory.read",
                dt.FORWARDABLE, [], 3600, reg, AT + 2, fx["roots"],
                revocation=fx["revocation"])
        self.assertEqual(ctx.exception.code, "delegation-revoked")

    def test_substituted_revoker_refused(self):
        from gov import delegation_revocation as dr
        fx = self._receipt_ticket()
        evil = dr.DelegationRevoker(_seed("evil"), "evil")
        with self.assertRaises(dt.DelegationTicketError) as ctx:
            self._present(fx, AT + 5, {"revoker": evil})
        self.assertEqual(ctx.exception.code, "delegation-ticket-invalid")


if __name__ == "__main__":
    unittest.main()
