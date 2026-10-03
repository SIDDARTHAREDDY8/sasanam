"""Wave-297 lane 1 unit tests: gov/approval_request.

Red-first closure tests at the public seams (issue / verify_request /
matches_action / is_expired / validate_approver_data /
action_digest_for). Every coded refusal is asserted by code, not by
message.
"""

import copy
import time
import unittest

from gov import approval_request as AR
from gov import ed25519 as _ed

_SEED = bytes(range(32))
_SEED2 = bytes([255 - b for b in range(32)])
_NOW = 1798765432


def _issue(**kw):
    base = {
        "action_digest": "ab" * 32,
        "requester_agent_id": "agent-a",
        "requester_principal": "principal-a",
        "requester_pubkey_hex": _ed.publickey(_SEED).hex(),
        "context_digests": {"inputs": "cd" * 32, "policy": "ef" * 32},
        "approver_schema": [
            {"name": "blast_radius", "type": "enum",
             "values": ["canary-5pct", "full"], "required": True},
        ],
        "ttl_seconds": 3600,
        "issued_at": _NOW,
        "requester_seed": _SEED,
    }
    base.update(kw)
    return AR.issue(**base)


def _code_of(fn):
    try:
        fn()
    except AR.ApprovalRequestError as e:
        return e.code
    return None


class TestIssue(unittest.TestCase):
    def test_roundtrip(self):
        env = _issue()
        body = AR.verify_request(env, now=_NOW)
        self.assertEqual(body["action_digest"], "ab" * 32)
        self.assertEqual(body["schema"], "approval-request/v1")

    def test_seed_pubkey_mismatch(self):
        self.assertEqual(
            _code_of(lambda: _issue(requester_seed=_SEED2)),
            "approval-request-invalid")

    def test_ttl_bounds(self):
        self.assertEqual(_code_of(lambda: _issue(ttl_seconds=30)),
                         "approval-request-invalid")
        self.assertEqual(
            _code_of(lambda: _issue(ttl_seconds=31 * 24 * 3600)),
            "approval-request-invalid")

    def test_empty_context_digests(self):
        self.assertEqual(_code_of(lambda: _issue(context_digests={})),
                         "approval-request-digest-missing")

    def test_malformed_action_digest(self):
        self.assertEqual(_code_of(lambda: _issue(action_digest="zz")),
                         "approval-request-digest-missing")

    def test_duplicate_schema_field_names(self):
        schema = [{"name": "x", "type": "string", "required": False},
                  {"name": "x", "type": "string", "required": False}]
        self.assertEqual(_code_of(lambda: _issue(approver_schema=schema)),
                         "approval-request-invalid")

    def test_enum_without_values(self):
        schema = [{"name": "x", "type": "enum", "required": True}]
        self.assertEqual(_code_of(lambda: _issue(approver_schema=schema)),
                         "approval-request-invalid")


class TestVerify(unittest.TestCase):
    def test_post_freeze_mutation_is_forgery(self):
        env = _issue()
        env["request"]["ttl_seconds"] = 999999
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW)),
            "approval-request-forgery")

    def test_signature_swap_is_forgery(self):
        env = _issue()
        env["signature"] = _ed.sign(
            _SEED2, AR._canonical(env["request"])).hex()
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW)),
            "approval-request-forgery")

    def test_expired(self):
        env = _issue(ttl_seconds=100, issued_at=_NOW)
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW + 100)),
            "approval-request-expired")

    def test_exact_expiry_boundary(self):
        env = _issue(ttl_seconds=100, issued_at=_NOW)
        # One second inside the window verifies.
        self.assertTrue(AR.verify_request(env, now=_NOW + 99))

    def test_future_issued_at(self):
        env = _issue(issued_at=_NOW + 3600)
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW)),
            "approval-request-invalid")

    def test_unknown_envelope_key(self):
        env = _issue()
        env["extra"] = 1
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW)),
            "approval-request-invalid")

    def test_wrong_schema_marker(self):
        env = _issue()
        env["request"]["schema"] = "approval-request/v9"
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW)),
            "approval-request-invalid")

    def test_action_binding_mismatch(self):
        env = _issue(action_digest="ab" * 32)
        self.assertEqual(
            _code_of(lambda: AR.verify_request(
                env, expected_action_digest="ff" * 32, now=_NOW)),
            "approval-request-digest-missing")

    def test_action_binding_match(self):
        env = _issue(action_digest="ab" * 32)
        body = AR.verify_request(env, expected_action_digest="ab" * 32,
                                 now=_NOW)
        self.assertEqual(body["action_digest"], "ab" * 32)

    def test_requester_pin_mismatch(self):
        env = _issue()
        self.assertEqual(
            _code_of(lambda: AR.verify_request(
                env, expected_requester_pubkey_hex=_ed.publickey(
                    _SEED2).hex(), now=_NOW)),
            "approval-request-forgery")


class TestHelpers(unittest.TestCase):
    def test_action_digest_stable(self):
        a = {"tool": "shell", "args": {"cmd": "ls"}}
        self.assertEqual(AR.action_digest_for(a), AR.action_digest_for(a))

    def test_action_digest_sensitive_to_args(self):
        a = {"tool": "shell", "args": {"cmd": "ls"}}
        b = {"tool": "shell", "args": {"cmd": "rm -rf /"}}
        self.assertNotEqual(AR.action_digest_for(a), AR.action_digest_for(b))

    def test_matches_action(self):
        wall = int(time.time())
        env = _issue(action_digest="ab" * 32, ttl_seconds=3600,
                     issued_at=wall)
        self.assertTrue(AR.matches_action(env, "ab" * 32))
        self.assertFalse(AR.matches_action(env, "ff" * 32))

    def test_is_expired(self):
        env = _issue(ttl_seconds=100, issued_at=_NOW)
        self.assertFalse(AR.is_expired(env, now=_NOW + 50))
        self.assertTrue(AR.is_expired(env, now=_NOW + 100))

    def test_validate_approver_data_ok(self):
        schema = _issue()["request"]["approver_schema"]
        out = AR.validate_approver_data(schema, {"blast_radius": "full"})
        self.assertEqual(out, {"blast_radius": "full"})

    def test_validate_approver_data_missing_required(self):
        schema = _issue()["request"]["approver_schema"]
        self.assertEqual(
            _code_of(lambda: AR.validate_approver_data(schema, {})),
            "approval-request-invalid")

    def test_validate_approver_data_off_enum(self):
        schema = _issue()["request"]["approver_schema"]
        self.assertEqual(
            _code_of(lambda: AR.validate_approver_data(
                schema, {"blast_radius": "planet"})),
            "approval-request-invalid")

    def test_circular_body_is_invalid_not_raw(self):
        circ = {}
        circ["self"] = circ
        env = _issue()
        env["request"]["context_digests"] = {"loop": circ}
        self.assertEqual(
            _code_of(lambda: AR.verify_request(env, now=_NOW)),
            "approval-request-invalid")

    def test_deepcopy_of_envelope_verifies(self):
        env = _issue()
        env2 = copy.deepcopy(env)
        self.assertTrue(AR.verify_request(env2, now=_NOW))


if __name__ == "__main__":
    unittest.main()
