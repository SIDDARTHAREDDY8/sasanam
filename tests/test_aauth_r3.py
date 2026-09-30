"""Unit tests for gov/aauth_r3.py (wave-239 lane A).

AAuth R3 vocabulary grant tokens: closed vocabulary operation records,
r3_uri + r3_s256 content-addressed approval binding, granted/per-call
two-tier enforcement, per-call proposal challenge.
"""

import unittest

from gov import aauth_r3 as r3

VOCAB = "urn:aauth:vocabulary:mcp"


def _doc():
    return {
        "vocabulary": VOCAB,
        "operations": [
            {"tool": "list_calendar_events"},
            {"tool": "send_email", "server": "mail-1"},
        ],
    }


def _token():
    return r3.issue_grant_token(
        _doc(),
        [{"tool": "list_calendar_events"}],
        [{"tool": "send_email", "server": "mail-1"}],
        r3_uri="r3://issuer/doc1")


class R3ContentAddressTests(unittest.TestCase):
    def test_s256_is_deterministic(self):
        doc = _doc()
        self.assertEqual(r3.r3_s256_of(doc), r3.r3_s256_of(dict(doc)))

    def test_s256_changes_when_document_changes(self):
        doc = _doc()
        edited = {"vocabulary": VOCAB,
                  "operations": doc["operations"] + [{"tool": "exfiltrate"}]}
        self.assertNotEqual(r3.r3_s256_of(doc), r3.r3_s256_of(edited))

    def test_s256_is_base64url_nopad(self):
        h = r3.r3_s256_of(_doc())
        self.assertTrue(h)
        self.assertNotIn("=", h)
        self.assertNotIn("+", h)
        self.assertNotIn("/", h)

    def test_token_pins_document_hash(self):
        self.assertEqual(_token()["r3_s256"], r3.r3_s256_of(_doc()))

    def test_token_pins_grant_hash(self):
        # Independent recompute: the pinned grant hash covers exactly the
        # issued (r3_granted, r3_per_call) lists -- not a literal copy.
        granted = [{"tool": "list_calendar_events"}]
        per_call = [{"tool": "send_email", "server": "mail-1"}]
        token = _token()
        self.assertEqual(token["r3_grant_hash"],
                         r3.grant_hash_of(granted, per_call))
        self.assertNotEqual(
            token["r3_grant_hash"],
            r3.grant_hash_of(granted + per_call, []))

    def test_bearer_widened_grant_refuses(self):
        # SPEC-BREAK fix (spec review): the grant lists are content-bound.
        # The bearer cannot silently re-widen a narrowed grant -- editing
        # r3_granted post-issuance refuses r3-grant-hash-mismatch.
        token = _token()
        token["r3_granted"] = (token["r3_granted"]
                               + [{"tool": "send_email",
                                   "server": "mail-1"}])
        with self.assertRaises(r3.R3Error) as cm:
            r3.verify_token(token, _doc())
        self.assertEqual(cm.exception.code, r3.R3_GRANT_HASH_MISMATCH)

    def test_bearer_promoted_per_call_refuses(self):
        # Promoting a per_call op into r3_granted is a widened grant too.
        token = _token()
        promoted = token["r3_per_call"][0]
        token["r3_granted"] = token["r3_granted"] + [promoted]
        token["r3_per_call"] = []
        with self.assertRaises(r3.R3Error) as cm:
            r3.verify_token(token, _doc())
        self.assertEqual(cm.exception.code, r3.R3_GRANT_HASH_MISMATCH)


class R3VocabularyTests(unittest.TestCase):
    def test_unregistered_vocabulary_refuses(self):
        doc = {"vocabulary": "urn:aauth:vocabulary:made-up", "operations": []}
        with self.assertRaises(r3.R3Error) as cm:
            r3.validate_document(doc)
        self.assertEqual(cm.exception.code, r3.R3_VOCABULARY_UNKNOWN)

    def test_non_string_vocabulary_is_malformed(self):
        # Spec-review minor note: empty/non-string vocab URIs are
        # shape violations (r3-malformed), distinct from unregistered
        # but well-formed URIs (r3-vocabulary-unknown).
        for bad in ("", None, 42):
            doc = {"vocabulary": bad, "operations": []}
            with self.assertRaises(r3.R3Error) as cm:
                r3.validate_document(doc)
            self.assertEqual(cm.exception.code, r3.R3_MALFORMED,
                             "vocab %r" % (bad,))

    def test_unknown_field_refuses(self):
        op = {"tool": "list_calendar_events", "sneaky": "yes"}
        with self.assertRaises(r3.R3Error) as cm:
            r3.validate_operation(VOCAB, op)
        self.assertEqual(cm.exception.code, r3.R3_UNKNOWN_OPERATION)

    def test_missing_required_field_refuses(self):
        with self.assertRaises(r3.R3Error) as cm:
            r3.validate_operation(VOCAB, {"server": "mail-1"})
        self.assertEqual(cm.exception.code, r3.R3_UNKNOWN_OPERATION)

    def test_non_string_value_refuses(self):
        with self.assertRaises(r3.R3Error) as cm:
            r3.validate_operation(VOCAB, {"tool": 42})
        self.assertEqual(cm.exception.code, r3.R3_UNKNOWN_OPERATION)

    def test_valid_operation_passes(self):
        op = {"tool": "send_email", "server": "mail-1", "arguments": "hi"}
        self.assertEqual(r3.validate_operation(VOCAB, op), op)


class R3IssueTests(unittest.TestCase):
    def test_grant_beyond_document_refuses(self):
        doc = _doc()
        with self.assertRaises(r3.R3Error) as cm:
            r3.issue_grant_token(doc, [{"tool": "exfiltrate"}],
                                 r3_uri="r3://issuer/doc1")
        self.assertEqual(cm.exception.code, r3.R3_GRANT_BEYOND_DOCUMENT)

    def test_narrowing_grant_is_allowed(self):
        doc = _doc()
        token = r3.issue_grant_token(doc, [{"tool": "list_calendar_events"}],
                                     r3_uri="r3://issuer/doc1")
        self.assertEqual(token["r3_granted"],
                         [{"tool": "list_calendar_events"}])
        self.assertEqual(token["r3_per_call"], [])

    def test_missing_r3_uri_refuses(self):
        with self.assertRaises(r3.R3Error) as cm:
            r3.issue_grant_token(_doc(), [], r3_uri="")
        self.assertEqual(cm.exception.code, r3.R3_MALFORMED)

    def test_document_unknown_member_refuses(self):
        doc = _doc()
        doc["extra"] = "nope"
        with self.assertRaises(r3.R3Error) as cm:
            r3.validate_document(doc)
        self.assertEqual(cm.exception.code, r3.R3_MALFORMED)


class R3VerifyTests(unittest.TestCase):
    def test_hash_mismatch_refuses(self):
        token = _token()
        edited = {"vocabulary": VOCAB,
                  "operations": [{"tool": "list_calendar_events"}]}
        with self.assertRaises(r3.R3Error) as cm:
            r3.verify_token(token, edited)
        self.assertEqual(cm.exception.code, r3.R3_S256_MISMATCH)

    def test_happy_path_verifies(self):
        token = _token()
        uri, pinned, grant_pinned, granted, per_call = r3.verify_token(
            token, _doc())
        self.assertEqual(uri, "r3://issuer/doc1")
        self.assertEqual(pinned, token["r3_s256"])
        self.assertEqual(grant_pinned, token["r3_grant_hash"])
        self.assertEqual(granted, [{"tool": "list_calendar_events"}])
        self.assertEqual(
            per_call, [{"tool": "send_email", "server": "mail-1"}])


class R3EnforcementTests(unittest.TestCase):
    def test_granted_serves(self):
        token = _token()
        self.assertEqual(
            r3.check_access(token, _doc(), {"tool": "list_calendar_events"}),
            r3.SERVE)

    def test_per_call_challenges(self):
        token = _token()
        self.assertEqual(
            r3.check_access(token, _doc(),
                            {"tool": "send_email", "server": "mail-1"}),
            r3.CHALLENGE)

    def test_no_match_refuses(self):
        token = _token()
        with self.assertRaises(r3.R3Error) as cm:
            r3.check_access(token, _doc(),
                            {"tool": "list_calendar_events",
                             "server": "mail-1"})
        self.assertEqual(cm.exception.code, r3.R3_NO_MATCH)


class R3PerCallTests(unittest.TestCase):
    def _proposal(self):
        op = {"tool": "send_email", "server": "mail-1",
              "arguments": "hi-alice"}
        proposal = {"vocabulary": VOCAB, "operations": [op]}
        token = r3.issue_per_call_token(_doc(), op,
                                        r3_uri="r3://issuer/proposal-7")
        return token, proposal, op

    def test_per_call_pins_proposal_hash(self):
        token, proposal, _op = self._proposal()
        self.assertEqual(token["r3_s256"], r3.r3_s256_of(proposal))

    def test_exact_bind_serves(self):
        token, proposal, op = self._proposal()
        self.assertEqual(r3.challenge_per_call(token, proposal, op),
                         r3.SERVE)

    def test_edited_params_refuse(self):
        token, proposal, op = self._proposal()
        edited = dict(op)
        edited["arguments"] = "hi-alice,also-bob"
        with self.assertRaises(r3.R3Error) as cm:
            r3.challenge_per_call(token, proposal, edited)
        self.assertEqual(cm.exception.code, r3.R3_PER_CALL_BINDING_BROKEN)

    def test_edited_proposal_refuses_as_hash_mismatch(self):
        token, proposal, op = self._proposal()
        tampered = {"vocabulary": VOCAB,
                    "operations": [dict(op, arguments="hi-eve")]}
        with self.assertRaises(r3.R3Error) as cm:
            r3.challenge_per_call(token, tampered, op)
        self.assertEqual(cm.exception.code, r3.R3_S256_MISMATCH)


class R3AuditTests(unittest.TestCase):
    def test_audit_provenance(self):
        token = _token()
        prov = r3.audit_provenance(token)
        self.assertEqual(prov, {"r3_uri": "r3://issuer/doc1",
                               "r3_s256": token["r3_s256"]})


if __name__ == "__main__":
    unittest.main()
