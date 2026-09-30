#!/usr/bin/env python3
"""Unit tests for gov.mcp_invocation_authz (wave-218, lane B).

COAZ-MCP ADAPT (idea only): TOCTOU permit-message binding, trust-
anchored subject.id with top-level-subject-only discipline, and
tighten-only server-advertised-mapping pinning.

Deterministic (no clock, no randomness); stdlib-only plus gov.
"""

import copy
import os
import sys
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import mcp_invocation_authz as mia  # noqa: E402


_MAPPING = {
    "files": {
        "read": {"description": "read",
                 "inputSchema": {"type": "object"}},
        "write": {"description": "write",
                  "inputSchema": {"type": "object"}},
    },
}
_PIN = mia.canonical_digest(_MAPPING)


def _policy(**over):
    spec = {"subject_id": "alice", "pinned_mapping_digest": _PIN}
    spec.update(over)
    return mia.build_policy(spec)


def _message(**over):
    msg = {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
           "params": {"name": "read", "arguments": {"path": "/tmp/a"}}}
    msg.update(over)
    return msg


def _context(subject_id="alice", mapping=None):
    mapping = _MAPPING if mapping is None else mapping
    return {"subject": {"id": subject_id},
            "server_mapping": copy.deepcopy(mapping)}


class BuildPolicyTests(unittest.TestCase):
    def test_valid_spec(self):
        p = _policy()
        self.assertEqual(p.subject_id, "alice")
        self.assertEqual(p.pinned_mapping_digest, _PIN)

    def test_unpinned_allowed_at_build(self):
        p = mia.build_policy({"subject_id": "alice",
                              "pinned_mapping_digest": None})
        self.assertIsNone(p.pinned_mapping_digest)

    def test_unknown_key_raises(self):
        with self.assertRaises(mia.McpInvocationAuthzError):
            mia.build_policy({"subject_id": "alice", "bogus": 1})

    def test_missing_subject_raises(self):
        with self.assertRaises(mia.McpInvocationAuthzError):
            mia.build_policy({"pinned_mapping_digest": _PIN})

    def test_empty_subject_raises(self):
        with self.assertRaises(mia.McpInvocationAuthzError):
            mia.build_policy({"subject_id": "   "})

    def test_non_string_subject_raises(self):
        with self.assertRaises(mia.McpInvocationAuthzError):
            mia.build_policy({"subject_id": 42})

    def test_malformed_pin_raises(self):
        for bad in ("zz", "sha256:" + "zz" * 32, "sha256:" + "aa" * 31,
                    "sha256:" + "AA" * 32, 123):
            with self.assertRaises(mia.McpInvocationAuthzError,
                                   msg="pin=%r" % (bad,)):
                mia.build_policy({"subject_id": "alice",
                                  "pinned_mapping_digest": bad})

    def test_non_mapping_spec_raises(self):
        with self.assertRaises(mia.McpInvocationAuthzError):
            mia.build_policy("nope")


class CanonicalDigestTests(unittest.TestCase):
    def test_deterministic_and_sorted(self):
        self.assertEqual(mia.canonical_digest({"b": 1, "a": 2}),
                         mia.canonical_digest({"a": 2, "b": 1}))

    def test_shape(self):
        d = mia.canonical_digest({"x": 1})
        self.assertTrue(d.startswith("sha256:") and len(d) == 7 + 64)

    def test_non_serializable_raises(self):
        with self.assertRaises(mia.McpInvocationAuthzError):
            mia.canonical_digest({"f": object()})


class AuthorizeTests(unittest.TestCase):
    def test_happy_path(self):
        out = mia.authorize(_policy(), _message(), _context())
        self.assertEqual(out.verdict, "permit")
        self.assertEqual(out.code, "permit")
        self.assertIsNotNone(out.permit)
        self.assertEqual(out.permit["format"], mia.FORMAT_PERMIT)
        self.assertEqual(out.permit["subject_id"], "alice")
        self.assertEqual(out.permit["mapping_digest"], _PIN)
        self.assertEqual(out.permit["tool"], "read")
        self.assertEqual(out.permit["method"], "tools/call")

    def test_permit_binds_message_digest(self):
        out = mia.authorize(_policy(), _message(), _context())
        self.assertEqual(out.permit["message_digest"],
                         mia.canonical_digest(_message()))

    def test_drift_refused(self):
        drifted = {"files": dict(_MAPPING["files"])}
        drifted["files"]["exec"] = {"description": "x",
                                    "inputSchema": {"type": "object"}}
        out = mia.authorize(_policy(), _message(), _context(mapping=drifted))
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MAPPING_DRIFT))

    def test_unpinned_refused(self):
        p = _policy(pinned_mapping_digest=None)
        out = mia.authorize(p, _message(), _context())
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MAPPING_UNPINNED))

    def test_subject_missing_refused(self):
        out = mia.authorize(_policy(), _message(),
                            {"server_mapping": _MAPPING})
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.SUBJECT_UNANCHORED))

    def test_subject_mismatch_refused(self):
        out = mia.authorize(_policy(), _message(),
                            _context(subject_id="mallory"))
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.SUBJECT_UNANCHORED))

    def test_smuggling_refused(self):
        msg = _message(params={"name": "read",
                               "arguments": {"path": "/tmp/a"},
                               "subject": {"id": "mallory"}})
        out = mia.authorize(_policy(), msg, _context())
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.SUBJECT_SMUGGLING))

    def test_echo_is_untrusted_not_refused(self):
        msg = _message(params={"name": "read",
                               "arguments": {"path": "/tmp/a"},
                               "subject": {"id": "alice"}})
        out = mia.authorize(_policy(), msg, _context())
        self.assertEqual(out.verdict, "permit")
        self.assertTrue(any("subject" in c
                            for c in out.report["untrusted_subject_claims"]))

    def test_nested_actor_recorded_untrusted(self):
        msg = _message(params={"name": "read",
                               "arguments": {"path": "/tmp/a"},
                               "metadata": {"actor": "alice"}})
        out = mia.authorize(_policy(), msg, _context())
        self.assertEqual(out.verdict, "permit")
        self.assertIn("$.message.params.metadata.actor",
                      out.report["untrusted_subject_claims"])

    def test_malformed_message_never_raises(self):
        for bad in ("x", None, {"id": 1}, {"method": 5}):
            out = mia.authorize(_policy(), bad, _context())
            self.assertEqual((out.verdict, out.code),
                             ("refuse", mia.MALFORMED_MESSAGE),
                             msg="message=%r" % (bad,))

    def test_malformed_context_never_raises(self):
        out = mia.authorize(_policy(), _message(), "x")
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_CONTEXT))
        out = mia.authorize(_policy(), _message(),
                            {"subject": {"id": "alice"}})
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_CONTEXT))

    def test_circular_message_refused(self):
        # A self-referential dict must not hang the nested-claim scan;
        # it refuses as malformed once canonicalization fails.
        msg = _message()
        msg["self"] = msg
        out = mia.authorize(_policy(), msg, _context())
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_MESSAGE))

    def test_circular_context_refused(self):
        ctx = _context()
        ctx["server_mapping"]["loop"] = ctx["server_mapping"]
        out = mia.authorize(_policy(), _message(), ctx)
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_CONTEXT))

    def test_wrong_policy_type_refused(self):
        out = mia.authorize({"subject_id": "alice"}, _message(), _context())
        self.assertEqual(out.verdict, "refuse")


class ApplyPermitTests(unittest.TestCase):
    def _permit(self, policy=None, message=None, ctx=None):
        policy = policy or _policy()
        message = message or _message()
        ctx = ctx or _context()
        res = mia.authorize(policy, message, ctx)
        self.assertEqual(res.verdict, "permit")
        return res.permit

    def test_happy_path_applies(self):
        permit = self._permit()
        out = mia.apply_permit(permit, _message(), _context())
        self.assertEqual((out.verdict, out.code), ("apply", "apply"))

    def test_applies_without_context(self):
        permit = self._permit()
        out = mia.apply_permit(permit, _message())
        self.assertEqual((out.verdict, out.code), ("apply", "apply"))

    def test_any_mutation_refused(self):
        permit = self._permit()
        mutations = [
            _message(params={"name": "read",
                             "arguments": {"path": "/etc/passwd"}}),
            _message(method="tools/list"),
            _message(params={"name": "write",
                             "arguments": {"path": "/tmp/a"}}),
            _message(id=123),
            _message(jsonrpc="1.0"),
        ]
        for i, tampered in enumerate(mutations):
            out = mia.apply_permit(permit, tampered)
            self.assertEqual((out.verdict, out.code),
                             ("refuse", mia.PERMIT_MESSAGE_MISMATCH),
                             msg="mutation %d" % i)

    def test_subject_reanchored(self):
        permit = self._permit()
        out = mia.apply_permit(permit, _message(),
                               _context(subject_id="mallory"))
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.SUBJECT_UNANCHORED))

    def test_bogus_permit_refused(self):
        out = mia.apply_permit({"format": "nope"}, _message())
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_PERMIT))
        out = mia.apply_permit("permit", _message())
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_PERMIT))

    def test_malformed_message_at_apply_never_raises(self):
        permit = self._permit()
        out = mia.apply_permit(permit, "x")
        self.assertEqual((out.verdict, out.code),
                         ("refuse", mia.MALFORMED_MESSAGE))


if __name__ == "__main__":
    unittest.main(verbosity=2)
