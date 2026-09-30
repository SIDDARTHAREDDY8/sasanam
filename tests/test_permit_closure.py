#!/usr/bin/env python3
"""Unit tests for gov/permit_closure.py (wave-236 lane C).

Boundary pins at the public seams: JCS canonicalization binds
byte-different JSON wire shapes; every refusal carries its exact
machine code; tamper checks precede the binding check so an edited
record cannot reach dispatch; closures narrow, never widen.
"""

import unittest

from gov import permit_closure as pc


def _decision():
    return {"action": "deploy", "target": "prod", "decision": "permit"}


def _request_json():
    return b'{"action":"deploy","params":{"tag":"v1.2.3"},"target":"prod"}'


def _scope():
    return ["deploy:prod", "deploy:staging", "logs:read"]


def _issue(**kwargs):
    args = dict(decision=_decision(), request_bytes=_request_json(),
                scope=_scope())
    args.update(kwargs)
    return pc.issue_permit(**args)


def _code(exc):
    return getattr(exc, "code", None)


class PermitIssuanceTest(unittest.TestCase):
    def test_permit_seals_and_verifies(self):
        permit = _issue()
        self.assertTrue(pc.verify_permit(permit))
        self.assertEqual(len(permit["permit_digest"]), 64)

    def test_byte_different_json_wire_shape_still_binds(self):
        permit = _issue()
        # Key order and whitespace differ; semantics identical.
        other = b'{"target":"prod", "action":"deploy", "params": ' \
                b'{"tag":"v1.2.3"}}'
        self.assertTrue(pc.dispatch(permit, other))

    def test_opaque_bytes_bound_byte_exact(self):
        opaque = b"\x00\x01non-json-payload"
        permit = _issue(request_bytes=opaque)
        self.assertTrue(pc.dispatch(permit, opaque))
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.dispatch(permit, b"\x00\x02non-json-payload")
        self.assertEqual(_code(ctx.exception), "permit-binding-mismatch")

    def test_empty_request_bytes_refused(self):
        with self.assertRaises(pc.PermitClosureError) as ctx:
            _issue(request_bytes=b"")
        self.assertEqual(_code(ctx.exception), "permit-malformed")

    def test_empty_scope_refused(self):
        with self.assertRaises(pc.PermitClosureError) as ctx:
            _issue(scope=[])
        self.assertEqual(_code(ctx.exception), "permit-malformed")


class DispatchRefusalsTest(unittest.TestCase):
    def test_dispatch_without_permit(self):
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.dispatch(None, _request_json())
        self.assertEqual(_code(ctx.exception), "dispatch-without-permit")

    def test_binding_mismatch(self):
        permit = _issue()
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.dispatch(permit,
                        b'{"action":"deploy","params":{"tag":"v9.9.9"},'
                        b'"target":"prod"}')
        self.assertEqual(_code(ctx.exception), "permit-binding-mismatch")

    def test_tampered_permit_never_reaches_dispatch(self):
        permit = _issue()
        tampered = dict(permit)
        tampered["scope"] = ["*"]
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.dispatch(tampered, _request_json())
        self.assertEqual(_code(ctx.exception), "permit-tampered")

    def test_edited_request_digest_refused_as_tampered(self):
        permit = _issue()
        tampered = dict(permit)
        tampered["request_digest"] = "cd" * 32
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_permit(tampered)
        self.assertEqual(_code(ctx.exception), "permit-tampered")


class ClosureTest(unittest.TestCase):
    def test_closure_verifies_with_permit(self):
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32,
                                   ["deploy:prod", "logs:read"])
        self.assertTrue(pc.verify_closure(closure, permit))

    def test_empty_effects_closure_verifies(self):
        # A closure that took nothing narrowed to the empty set.
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32, [])
        self.assertTrue(pc.verify_closure(closure, permit))

    def test_closure_without_permit(self):
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32, ["deploy:prod"])
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_closure(closure, None)
        self.assertEqual(_code(ctx.exception), "closure-permit-absent")

    def test_closure_permit_mismatch(self):
        permit = _issue()
        other = _issue()
        closure = pc.issue_closure(other, "ab" * 32, ["deploy:prod"])
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_closure(closure, permit)
        self.assertEqual(_code(ctx.exception), "closure-permit-mismatch")

    def test_closure_widened_refused(self):
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32,
                                   ["deploy:prod", "secrets:read"])
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_closure(closure, permit)
        self.assertEqual(_code(ctx.exception), "closure-scope-widened")

    def test_tampered_closure_refused(self):
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32, ["deploy:prod"])
        tampered = dict(closure)
        tampered["effects"] = ["deploy:prod", "logs:read"]
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_closure(tampered, permit)
        self.assertEqual(_code(ctx.exception), "permit-tampered")

    def test_closure_for_tampered_permit_refused(self):
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32, ["deploy:prod"])
        tampered_permit = dict(permit)
        tampered_permit["scope"] = ["*"]
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_closure(closure, tampered_permit)
        self.assertEqual(_code(ctx.exception), "permit-tampered")

    def test_bad_outcome_digest_refused(self):
        permit = _issue()
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.issue_closure(permit, "not-a-digest", ["deploy:prod"])
        self.assertEqual(_code(ctx.exception), "permit-malformed")

    def test_non_string_scope_refused(self):
        permit = _issue()
        closure = pc.issue_closure(permit, "ab" * 32, ["deploy:prod"])
        tampered = dict(permit)
        tampered["scope"] = ["deploy:prod", 42]
        with self.assertRaises(pc.PermitClosureError) as ctx:
            pc.verify_closure(closure, tampered)
        self.assertEqual(_code(ctx.exception), "permit-malformed")


if __name__ == "__main__":
    unittest.main()
