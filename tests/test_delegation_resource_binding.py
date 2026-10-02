"""Wave-278: RFC 8707 resource binding for the three-token delegation.

Unit-pins for gov/delegation_tokens.py resource binding: signed
``resource`` claim at mint, spawn inheritance (never a parameter),
verifier-declared enforcement at authorize/bind/enforce_tool_call,
fail-fast malformed URIs, signature coverage of the claim, and
byte-identical legacy behavior when nothing is declared.

Hermetic: synthetic keys via generate_test_keypair, no network, no PKI.
Deterministic except wall-clock iat/exp (never asserted on).
"""

import copy
import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov import delegation_tokens as _dt  # noqa: E402
from gov.identity import AgentIdentity  # noqa: E402

_SID = "sess-w278-unit"
_REVOKE_URI = "https://revoke.example.invalid/deleg"
_RSRC_A = "https://mcp-a.example.invalid/server"
_RSRC_B = "https://mcp-b.example.invalid/server"


class _Keys(object):
    def __init__(self):
        self.human = _dt.generate_test_keypair()
        self.idp = _dt.generate_test_keypair()
        self.authority = _dt.generate_test_keypair()
        self.parent = _dt.generate_test_keypair()

    def trust(self):
        return _dt.DelegationTrust(
            human_keys={self.human[0].key_id: self.human[1]},
            authority_keys={self.authority[0].key_id: self.authority[1]},
            user_issuer_keys={self.idp[0].key_id: self.idp[1]},
            agent_keys={"agent-1": self.parent[1]})


def _trio(keys, session=_SID, resource=None):
    kw = {} if resource is None else {"resource": resource}
    user_tok = _dt.issue_user_token(keys.idp[0], "user-7",
                                    ("tool:read_file",), session, ttl_s=3600)
    agent_tok = _dt.issue_agent_token(keys.authority[0], "agent-1",
                                      "scout", "user-7",
                                      ("tool:read_file",), session,
                                      ttl_s=3600)
    deleg_tok = _dt.issue_delegation(
        keys.human[0], "user-7", user_tok, agent_tok,
        ("tool:read_file",), session, _REVOKE_URI, ttl_s=3600, **kw)
    return user_tok, agent_tok, deleg_tok


def _ctx(keys, trust, toks, session=_SID, bind_resource=None):
    kw = {} if bind_resource is None else {
        "expected_resource": bind_resource}
    return _dt.DelegationContext(
        user_token=toks[0], agent_token=toks[1],
        delegation_token=toks[2], parent_chain=[],
        trust=trust, session_id=session).bind(**kw)


class ResourceBindingTest(unittest.TestCase):
    def test_mint_carries_signed_resource(self):
        keys = _Keys()
        toks = _trio(keys, resource=_RSRC_A)
        self.assertEqual(toks[2]["resource"], _RSRC_A)

    def test_legacy_mint_has_no_resource(self):
        keys = _Keys()
        toks = _trio(keys)
        self.assertNotIn("resource", toks[2])

    def test_cross_server_refused(self):
        keys = _Keys()
        trust = keys.trust()
        ctx = _ctx(keys, trust, _trio(keys, resource=_RSRC_A))
        with self.assertRaises(_dt.DelegationBindingError):
            ctx.authorize("tool:read_file", _RSRC_B)

    def test_same_server_allowed(self):
        keys = _Keys()
        trust = keys.trust()
        ctx = _ctx(keys, trust, _trio(keys, resource=_RSRC_A))
        verdict = ctx.authorize("tool:read_file", _RSRC_A)
        self.assertEqual(verdict["action"], "tool:read_file")

    def test_unbound_token_refused_at_declared_resource(self):
        keys = _Keys()
        trust = keys.trust()
        ctx = _ctx(keys, trust, _trio(keys))  # no resource claim
        with self.assertRaises(_dt.DelegationBindingError):
            ctx.authorize("tool:read_file", _RSRC_A)

    def test_undeclared_use_unchanged(self):
        keys = _Keys()
        trust = keys.trust()
        # Bound token, no declaration: allowed (verifier-declared).
        ctx = _ctx(keys, trust, _trio(keys, resource=_RSRC_A))
        self.assertEqual(ctx.authorize("tool:read_file")["action"],
                         "tool:read_file")
        # Legacy token, no declaration: allowed (byte-identical).
        ctx2 = _ctx(keys, trust, _trio(keys))
        self.assertEqual(ctx2.authorize("tool:read_file")["action"],
                         "tool:read_file")

    def test_enforce_tool_call_threads_resource(self):
        keys = _Keys()
        trust = keys.trust()
        ctx = _ctx(keys, trust, _trio(keys, resource=_RSRC_A))
        ident = AgentIdentity(agent_id="agent-1", role="scout",
                              run_id=_SID, principal="user-7",
                              provenance="minted")
        with self.assertRaises(_dt.DelegationBindingError):
            _dt.enforce_tool_call(ctx, ident, "read_file",
                                  resource=_RSRC_B)
        ok = _dt.enforce_tool_call(ctx, ident, "read_file",
                                   resource=_RSRC_A)
        self.assertEqual(ok["action"], "tool:read_file")

    def test_spawn_inherits_resource(self):
        keys = _Keys()
        trust = keys.trust()
        parent = _ctx(keys, trust, _trio(keys, resource=_RSRC_A))
        child = parent.spawn("agent-2", ("tool:read_file",),
                             keys.parent[0])
        self.assertEqual(child.delegation_token["resource"], _RSRC_A)
        with self.assertRaises(_dt.DelegationBindingError):
            child.authorize("tool:read_file", _RSRC_B)
        self.assertEqual(
            child.authorize("tool:read_file", _RSRC_A)["action"],
            "tool:read_file")

    def test_spawn_of_legacy_parent_has_no_resource(self):
        keys = _Keys()
        trust = keys.trust()
        parent = _ctx(keys, trust, _trio(keys))
        child = parent.spawn("agent-2", ("tool:read_file",),
                             keys.parent[0])
        self.assertNotIn("resource", child.delegation_token)

    def test_bind_with_expected_resource(self):
        keys = _Keys()
        trust = keys.trust()
        toks = _trio(keys, resource=_RSRC_A)
        _ctx(keys, trust, toks, bind_resource=_RSRC_A)  # binds fine
        with self.assertRaises(_dt.DelegationBindingError):
            _ctx(keys, trust, toks, bind_resource=_RSRC_B)

    def test_malformed_resource_refused_at_mint(self):
        keys = _Keys()
        for bad in ("not-a-uri", "http://plain.example/x", "", "https://",
                    "https://exa mple.invalid/x", 42):
            with self.assertRaises(ValueError, msg="resource=%r" % (bad,)):
                _trio(keys, resource=bad)

    def test_resource_claim_is_signature_covered(self):
        keys = _Keys()
        trust = keys.trust()
        toks = _trio(keys, resource=_RSRC_A)
        tampered = copy.deepcopy(toks[2])
        tampered["resource"] = _RSRC_B
        ctx = _dt.DelegationContext(
            user_token=toks[0], agent_token=toks[1],
            delegation_token=tampered, parent_chain=[],
            trust=trust, session_id=_SID)
        with self.assertRaises(_dt.DelegationSignatureError):
            ctx.bind()

    def test_verify_token_seam(self):
        keys = _Keys()
        trust = keys.trust()
        toks = _trio(keys, resource=_RSRC_A)
        _dt.verify_token(toks[2], trust.human_keys,
                         expected_kind="delegation",
                         expected_session=_SID,
                         expected_resource=_RSRC_A)
        with self.assertRaises(_dt.DelegationBindingError):
            _dt.verify_token(toks[2], trust.human_keys,
                             expected_kind="delegation",
                             expected_session=_SID,
                             expected_resource=_RSRC_B)


if __name__ == "__main__":
    unittest.main()
