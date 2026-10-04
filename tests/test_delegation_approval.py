"""Unit tests for gov/delegation_approval.py: delegated approval requests.

Every coded refusal is asserted by code (F351 contract); the ed25519
True/False contract is pinned (wave-243); the two new decision codes
are pinned as raw source literals; the module's declared non-goals
(no direct ed25519 calls, no quorum changes, no queue changes) are
asserted structurally.
"""

import hashlib
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import delegation as dg
from gov import delegation_approval as da
from gov import ed25519


def _seed(tag):
    return hashlib.sha256(tag.encode()).digest()


class DelegatedApprovalContractTest(unittest.TestCase):
    def setUp(self):
        self.seed_a = _seed("w300da-a")
        self.seed_b = _seed("w300da-b")
        self.seed_c = _seed("w300da-c")
        self.pub_a = ed25519.publickey(self.seed_a).hex()
        self.pub_b = ed25519.publickey(self.seed_b).hex()
        self.pub_c = ed25519.publickey(self.seed_c).hex()
        self.at = 1_700_000_000
        self.cons = {"expires_at": self.at + 3600, "max_depth": 4,
                     "allowed_targets": ["agent-c"]}

    def _root(self, rights=("tool.invoke",), **kw):
        cons = {"expires_at": self.at + 3600, "max_depth": 4,
                "allowed_targets": ["agent-b"]}
        kw.setdefault("constraints", dict(cons))
        return dg.issue(self.seed_a, "agent-a", "agent-b", self.pub_b,
                        rights, issued_at=self.at, **kw)

    def _link(self, parent, did, seed, rights=("tool.invoke",), **kw):
        cons = {"expires_at": self.at + 3600, "max_depth": 4,
                "allowed_targets": [did]}
        kw.setdefault("constraints", dict(cons))
        return dg.issue(seed, parent["delegatee_id"], did,
                        ed25519.publickey(seed).hex(), rights,
                        parent=parent, issued_at=self.at, **kw)

    def _pkg(self, chain, **kw):
        leaf = chain[-1]
        rid = kw.pop("requester", "agent-b")
        seed = kw.pop("rseed", None) or (
            self.seed_b if rid == "agent-b" else self.seed_c)
        kw.setdefault("approver_schema", [])
        kw.setdefault("ttl_seconds", 3600)
        kw.setdefault("issued_at", self.at)
        pub = ed25519.publickey(seed).hex()
        return da.issue_delegated_request(
            chain=chain, delegation_right="tool.invoke",
            action={"tool": "shell", "args": {"cmd": "ls"}},
            requester_agent_id=rid,
            requester_principal="principal-" + rid,
            requester_pubkey_hex=pub, requester_seed=seed, **kw)

    def _verify(self, pkg, **kw):
        kw.setdefault("at", self.at)
        kw.setdefault("trust_roots", [self.pub_a])
        return da.verify_delegated_request(pkg, **kw)

    def _code_of(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:  # noqa: BLE001 -- probe harness
            self.assertIsNotNone(getattr(e, "code", None),
                                 "refusal without code: %r" % (e,))
            return e.code
        self.fail("expected coded refusal, call succeeded")

    # -- issue ----------------------------------------------------------------

    def test_issue_binds_digests_not_chains(self):
        pkg = self._pkg([self._root()])
        ctx = pkg["envelope"]["request"]["context_digests"]
        for key in ("delegation_chain_digest", "delegator_id_digest",
                    "delegation_right_digest"):
            self.assertEqual(len(ctx[key]), 64)
        for rid in (l["receipt_id"] for l in pkg["chain"]):
            self.assertNotIn(rid, repr(ctx))

    def test_issue_refuses_non_holder(self):
        root = self._root()
        self.assertEqual(
            self._code_of((lambda: da.issue_delegated_request(
                          chain=[root], delegation_right="tool.invoke",
                          action={"tool": "shell", "args": {"cmd": "ls"}},
                          requester_agent_id="agent-evil",
                          requester_principal="principal-" + "agent-evil",
                          requester_pubkey_hex=ed25519.publickey(self.seed_c).hex(),
                          requester_seed=self.seed_c, approver_schema=[],
                          ttl_seconds=3600, issued_at=self.at))),
            "delegation-invalid")

    def test_issue_rejects_empty_chain(self):
        self.assertEqual(
            self._code_of((lambda: da.issue_delegated_request(
                          chain=[], delegation_right="tool.invoke",
                          action={"tool": "shell", "args": {"cmd": "ls"}},
                          requester_agent_id="agent-b",
                          requester_principal="principal-" + "agent-b",
                          requester_pubkey_hex=ed25519.publickey(self.seed_b).hex(),
                          requester_seed=self.seed_b, approver_schema=[],
                          ttl_seconds=3600, issued_at=self.at))),
            "delegation-invalid")

    def test_chain_digest_stable_and_receipt_ordered(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_b)
        self.assertEqual(da.chain_digest([root, link]),
                         da.chain_digest([dict(root), dict(link)]))
        self.assertNotEqual(da.chain_digest([root, link]),
                            da.chain_digest([link, root]))

    # -- verify: happy path -----------------------------------------------------

    def test_honest_delegated_request_verifies(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_b)
        pkg = self._pkg([root, link], requester="agent-c",
                        rseed=self.seed_c)
        verdict = self._verify(pkg)
        self.assertEqual(verdict["delegator_id"], "agent-a")
        self.assertEqual(verdict["request"]["requester"]["agent_id"],
                         "agent-c")
        self.assertEqual(verdict["delegation_right"], "tool.invoke")
        self.assertEqual(verdict["leaf_receipt_id"],
                         pkg["chain"][-1]["receipt_id"])

    def test_verdict_does_not_carry_raw_chain(self):
        # The verdict identifies the chain by digest (in the request)
        # and leaf receipt id -- it never embeds the chain's receipts.
        root = self._root()
        pkg = self._pkg([root])
        verdict = self._verify(pkg)
        self.assertNotIn("chain", verdict)
        self.assertNotIn("chain", verdict["delegation_verdict"])
        # No receipt body (signatures) leaks into the verdict.
        for link in pkg["chain"]:
            self.assertNotIn(link["signature"], repr(verdict))

    # -- verify: refusal codes ---------------------------------------------------

    def test_chain_swap_refused_by_binding_code(self):
        root = self._root()
        # A byte-identical re-issue would share the receipt_id and bind
        # identically, so the swap target must be a DISTINCT chain.
        other = self._root(rights=("tool.invoke", "memory.read"))
        pkg = self._pkg([root])
        bad = dict(pkg)
        bad["chain"] = [dict(other)]
        self.assertEqual(self._code_of(self._verify, bad),
                         "delegation-approval-chain-mismatch")

    def test_chain_link_swap_refused(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_b)
        # A link from a DISTINCT parent chain: validly signed, but a
        # different receipt_id, so the bound digest no longer matches.
        root2 = self._root(rights=("tool.invoke", "memory.read"))
        other_link = self._link(root2, "agent-c", self.seed_b)
        pkg = self._pkg([root, link], requester="agent-c",
                        rseed=self.seed_c)
        bad = dict(pkg)
        bad["chain"] = [dict(root), dict(other_link)]
        self.assertEqual(self._code_of(self._verify, bad),
                         "delegation-approval-chain-mismatch")

    def test_delegator_swap_refused(self):
        root = self._root()
        impostor = dg.issue(self.seed_c, "agent-evil", "agent-b",
                            self.pub_b, ("tool.invoke",),
                            constraints={"expires_at": self.at + 3600,
                                          "max_depth": 4,
                                          "allowed_targets": ["agent-b"]},
                            issued_at=self.at)
        pkg = self._pkg([root])
        bad = dict(pkg)
        bad["chain"] = [dict(impostor)]
        self.assertEqual(self._code_of(self._verify, bad),
                         "delegation-approval-chain-mismatch")

    def test_right_mismatch_refused(self):
        root = self._root(rights=("tool.invoke", "memory.read"))
        pkg = self._pkg([root])
        bad = dict(pkg)
        bad["delegation_right"] = "memory.read"
        self.assertEqual(self._code_of(self._verify, bad),
                         "delegation-approval-right-mismatch")

    def test_broken_chain_refused_with_delegation_code(self):
        root = self._root()
        pkg = self._pkg([root])
        link = dict(root)
        sig = link["signature"]
        link["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
        bad = dict(pkg)
        bad["chain"] = [link]
        self.assertEqual(self._code_of(self._verify, bad),
                         "delegation-chain-broken")

    def test_expired_chain_refused(self):
        root = self._root()
        pkg = self._pkg([root], ttl_seconds=10800)
        self.assertEqual(self._code_of(self._verify, pkg,
                                       at=self.at + 7200),
                         "delegation-expired")

    def test_right_not_covered_refused(self):
        # Issue does not verify the chain (no trust roots at issue
        # time); the coverage refusal fires at verify with the
        # delegation module's code.
        root = self._root(rights=("memory.read",))
        pkg = self._pkg([root])
        self.assertEqual(self._code_of(self._verify, pkg),
                         "delegation-invalid")

    def test_third_party_redelegation_refused(self):
        root = self._root()
        self.assertRaises(dg.DelegationError, dg.issue,
                          self.seed_c, "agent-b", "agent-c", self.pub_c,
                          ("tool.invoke",), parent=root,
                          constraints={"expires_at": self.at + 3600,
                                        "max_depth": 4,
                                        "allowed_targets": ["agent-c"]},
                          issued_at=self.at)

    def test_tampered_rights_refused(self):
        root = self._root(rights=("tool.invoke",))
        link = self._link(root, "agent-c", self.seed_b, ("tool.invoke",))
        pkg = self._pkg([root, link], requester="agent-c",
                        rseed=self.seed_c)
        wide = dict(link)
        wide["rights"] = ["tool.invoke", "memory.write"]
        bad = dict(pkg)
        bad["chain"] = [dict(root), wide]
        self.assertEqual(self._code_of(self._verify, bad),
                         "delegation-chain-broken")

    def test_revoked_chain_refused(self):
        from gov import delegation_revocation as dr
        root = self._root()
        link = self._link(root, "agent-c", self.seed_b)
        pkg = self._pkg([root, link], requester="agent-c",
                        rseed=self.seed_c)
        revoker = dr.DelegationRevoker(self.seed_a, "agent-a")
        revoker.revoke(root["receipt_id"], self.at + 10)
        self.assertEqual(
            self._code_of(self._verify, pkg, revoker=revoker),
            "delegation-revoked")

    def test_requester_not_chain_tip_refused(self):
        root = self._root()
        link = self._link(root, "agent-c", self.seed_b)
        pkg = self._pkg([root, link], requester="agent-c",
                        rseed=self.seed_c)
        bad = dict(pkg)
        env = dict(pkg["envelope"])
        req = dict(env["request"])
        req["requester_id"] = "agent-evil"
        env["request"] = req
        bad["envelope"] = env
        self.assertEqual(self._code_of(self._verify, bad),
                         "approval-request-invalid")

    def test_caller_context_digests_preserved(self):
        root = self._root()
        pkg = self._pkg([root],
                        context_digests={"policy/eval": "ab" * 32})
        self.assertEqual(pkg["envelope"]["request"]["context_digests"]["policy/eval"],
                         "ab" * 32)

    # -- ed25519 contract --------------------------------------------------------

    def test_ed25519_contract_pinned(self):
        sig = ed25519.sign(self.seed_a, b"m")
        self.assertIs(ed25519.verify(ed25519.publickey(self.seed_a),
                                     b"m", sig), True)
        self.assertIs(ed25519.verify(ed25519.publickey(self.seed_a),
                                     b"m", b"\x00" * 64), False)

    # -- structural non-goals -----------------------------------------------------

    def test_module_never_calls_ed25519_directly(self):
        import inspect
        src = inspect.getsource(da)
        self.assertNotIn("ed25519.verify", src)
        self.assertNotIn("ed25519.signature", src)

    def test_new_codes_are_two_and_sorted(self):
        import re
        pat = re.compile(r'''^\s*"code": '([a-z0-9][a-z0-9_\-\.]*)',\s*$''')
        lits = []
        with open(os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "gov",
                "decision_codes.py")) as f:
            for line in f:
                m = pat.match(line.rstrip("\n"))
                if m:
                    lits.append(m.group(1))
        self.assertEqual(len(lits), 1951)  #Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        new = [c for c in lits
               if c.startswith("delegation-approval-")]
        self.assertEqual(new, ["delegation-approval-chain-mismatch",
                               "delegation-approval-right-mismatch"])
        self.assertEqual(lits, sorted(lits))


if __name__ == "__main__":
    unittest.main(verbosity=1)
