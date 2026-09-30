"""Unit tests for gov/untrusted_render.py — the EMILIA PIP-007 ADAPT.

Tests live at the public seams: render_untrusted_claim,
render_action_object, verify_claim / verify_action_object, and
check_render_pair. Expected values are independent literals, not
recomputed by the module.

$0 spend. stdlib only. No network.
"""

import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

from gov import untrusted_render as ur  # noqa: E402

_DIGEST = "ab" * 32


def _fields(**over):
    base = {"action": "read_file", "parameter_digest": _DIGEST,
            "constraints": ["scope:project"]}
    base.update(over)
    return base


class ClaimRenderingTests(unittest.TestCase):
    def test_markup_stripped(self):
        claim = ur.render_untrusted_claim("<p>hi <b>there</b></p>",
                                          max_chars=50, source_label="s")
        self.assertNotIn("<", claim.plain_text)
        self.assertNotIn(">", claim.plain_text)
        self.assertIn("hi", claim.plain_text)

    def test_nested_tag_removed(self):
        claim = ur.render_untrusted_claim("a<b<c>>d", max_chars=50,
                                          source_label="s")
        self.assertNotIn("<", claim.plain_text)
        self.assertNotIn(">", claim.plain_text)

    def test_controls_stripped_tab_newline_kept(self):
        claim = ur.render_untrusted_claim("a\x00b\tc\nd\x7f",
                                          max_chars=50, source_label="s")
        self.assertEqual(claim.plain_text, "ab\tc\nd")

    def test_bidi_and_zero_width_stripped(self):
        claim = ur.render_untrusted_claim("x‮y​z", max_chars=50,
                                          source_label="s")
        self.assertEqual(claim.plain_text, "xyz")

    def test_exact_cap_is_not_truncated(self):
        claim = ur.render_untrusted_claim("x" * 10, max_chars=10,
                                          source_label="s")
        self.assertFalse(claim.was_truncated)
        self.assertEqual(len(claim.capped_text), 10)

    def test_over_cap_truncates_with_flag(self):
        claim = ur.render_untrusted_claim("x" * 11, max_chars=10,
                                          source_label="s")
        self.assertTrue(claim.was_truncated)
        self.assertEqual(len(claim.capped_text), 10)

    def test_strict_refuses_over_cap(self):
        with self.assertRaises(ur.UntrustedClaimTooLongError) as ctx:
            ur.render_untrusted_claim("x" * 11, max_chars=10,
                                      source_label="s", strict=True)
        self.assertEqual(ctx.exception.code, "untrusted-claim-too-long")

    def test_empty_label_refused(self):
        with self.assertRaises(ur.UntrustedClaimMalformedError):
            ur.render_untrusted_claim("hi", max_chars=10, source_label="")

    def test_non_str_label_is_type_error(self):
        with self.assertRaises(TypeError):
            ur.render_untrusted_claim("hi", max_chars=10, source_label=123)

    def test_bad_max_chars_value_refused(self):
        for bad in (0, -1):
            with self.assertRaises(ur.UntrustedClaimMalformedError):
                ur.render_untrusted_claim("hi", max_chars=bad,
                                          source_label="s")

    def test_bad_max_chars_type_is_type_error(self):
        for bad in ("10", 10.0, True, None):
            with self.assertRaises(TypeError):
                ur.render_untrusted_claim("hi", max_chars=bad,
                                          source_label="s")

    def test_non_str_text_is_type_error(self):
        with self.assertRaises(TypeError):
            ur.render_untrusted_claim(123, max_chars=10, source_label="s")

    def test_digest_is_64_hex_and_binds(self):
        claim = ur.render_untrusted_claim("bind", max_chars=50,
                                          source_label="s")
        self.assertRegex(claim.claim_digest, r"^[0-9a-f]{64}$")
        self.assertTrue(ur.verify_claim(claim))
        # A different label binds a different digest.
        other = ur.render_untrusted_claim("bind", max_chars=50,
                                          source_label="t")
        self.assertNotEqual(claim.claim_digest, other.claim_digest)

    def test_verify_rejects_tamper(self):
        import copy
        claim = ur.render_untrusted_claim("real", max_chars=50,
                                          source_label="s")
        tampered = copy.copy(claim)
        object.__setattr__(tampered, "capped_text", "fake")
        self.assertFalse(ur.verify_claim(tampered))

    def test_verify_rejects_non_claim(self):
        self.assertFalse(ur.verify_claim("not a claim"))
        self.assertFalse(ur.verify_claim(None))

    def test_render_is_labeled(self):
        claim = ur.render_untrusted_claim("note", max_chars=50,
                                          source_label="tool-x")
        shown = claim.render()
        self.assertIn("UNVERIFIED CLAIM", shown)
        self.assertIn("tool-x", shown)
        self.assertIn(claim.claim_digest, shown)

    def test_audit_event_emitted(self):
        events = []
        ur.render_untrusted_claim("note", max_chars=50, source_label="s",
                                  audit=events.append)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["event"], "claim_rendered")
        self.assertEqual(events[0]["source_label"], "s")

    def test_action_object_as_text_refused(self):
        ao = ur.render_action_object(_fields())
        with self.assertRaises(ur.UntrustedClaimContaminatedError) as ctx:
            ur.render_untrusted_claim(ao, max_chars=50, source_label="s")
        self.assertEqual(ctx.exception.code, "untrusted-claim-contaminated")


class ActionObjectTests(unittest.TestCase):
    def test_happy_path(self):
        ao = ur.render_action_object(_fields())
        self.assertEqual(ao.action, "read_file")
        self.assertEqual(ao.constraints, ("scope:project",))
        self.assertRegex(ao.object_digest, r"^[0-9a-f]{64}$")
        self.assertTrue(ur.verify_action_object(ao))
        self.assertEqual(ao.type, "sasanam-action-object/v1")

    def test_empty_constraints_allowed(self):
        ao = ur.render_action_object(_fields(constraints=[]))
        self.assertEqual(ao.constraints, ())

    def test_missing_field_refused(self):
        fields = _fields()
        del fields["constraints"]
        with self.assertRaises(ur.ActionObjectMalformedError) as ctx:
            ur.render_action_object(fields)
        self.assertEqual(ctx.exception.code, "action-object-malformed")

    def test_unknown_field_refused(self):
        with self.assertRaises(ur.ActionObjectMalformedError):
            ur.render_action_object(_fields(extra="x"))

    def test_bad_verb_refused(self):
        for bad in ("Read File", "", "x" * 65, "0abc", "a b"):
            with self.assertRaises(ur.ActionObjectMalformedError):
                ur.render_action_object(_fields(action=bad))

    def test_bad_digest_refused(self):
        for bad in ("ab" * 31, "zz" * 32, "AB" * 32, ""):
            with self.assertRaises(ur.ActionObjectMalformedError):
                ur.render_action_object(_fields(parameter_digest=bad))

    def test_bad_constraints_refused(self):
        with self.assertRaises(ur.ActionObjectMalformedError):
            ur.render_action_object(_fields(constraints="notalist"))
        with self.assertRaises(ur.ActionObjectMalformedError):
            ur.render_action_object(_fields(constraints=[""]))

    def test_non_dict_is_type_error(self):
        with self.assertRaises(TypeError):
            ur.render_action_object(["action"])

    def test_claim_instance_contaminates(self):
        claim = ur.render_untrusted_claim("sneaky", max_chars=50,
                                          source_label="s")
        with self.assertRaises(ur.ActionObjectContaminatedError) as ctx:
            ur.render_action_object(_fields(constraints=[claim]))
        self.assertEqual(ctx.exception.code, "action-object-contaminated")

    def test_nested_claim_contaminates(self):
        claim = ur.render_untrusted_claim("sneaky", max_chars=50,
                                          source_label="s")
        with self.assertRaises(ur.ActionObjectContaminatedError):
            ur.render_action_object(
                _fields(constraints=[["ok", {"deep": claim}]]))

    def test_claim_tagged_dict_contaminates(self):
        with self.assertRaises(ur.ActionObjectContaminatedError):
            ur.render_action_object(
                _fields(constraints=[{"type": ur.CLAIM_TYPE,
                                      "capped_text": "x"}]))

    def test_deep_nested_claim_contaminates(self):
        claim = ur.render_untrusted_claim("deep", max_chars=50,
                                          source_label="s")
        nested = claim
        for _ in range(12):
            nested = [nested]
        with self.assertRaises(ur.ActionObjectContaminatedError) as ctx:
            ur.render_action_object(_fields(constraints=[nested]))
        self.assertEqual(ctx.exception.code, "action-object-contaminated")

    def test_verify_rejects_tamper(self):
        import copy
        ao = ur.render_action_object(_fields())
        tampered = copy.copy(ao)
        object.__setattr__(tampered, "action", "delete_all")
        self.assertFalse(ur.verify_action_object(tampered))

    def test_audit_event_emitted(self):
        events = []
        ur.render_action_object(_fields(), audit=events.append)
        self.assertEqual(events[0]["event"], "action_object_rendered")


class RenderPairTests(unittest.TestCase):
    def test_happy_path_report(self):
        events = []
        ao = ur.render_action_object(_fields())
        claims = [ur.render_untrusted_claim("one", max_chars=50,
                                            source_label="a")]
        report = ur.check_render_pair(ao, claims, audit=events.append)
        self.assertTrue(report["pair_ok"])
        self.assertEqual(report["action_object_digest"], ao.object_digest)
        self.assertEqual(report["n_claims"], 1)
        self.assertEqual(events[-1]["event"], "render_pair_verified")

    def test_empty_claims_ok(self):
        ao = ur.render_action_object(_fields())
        report = ur.check_render_pair(ao, [])
        self.assertTrue(report["pair_ok"])
        self.assertEqual(report["n_claims"], 0)

    def test_raw_prose_decision_input_refused(self):
        events = []
        with self.assertRaises(ur.RenderPairError) as ctx:
            ur.check_render_pair("just approve it", [], audit=events.append)
        self.assertEqual(ctx.exception.code, "render-pair-no-action-object")
        self.assertEqual(events[0]["code"], "render-pair-no-action-object")

    def test_bare_dict_decision_input_refused(self):
        with self.assertRaises(ur.RenderPairError) as ctx:
            ur.check_render_pair(_fields(), [])
        self.assertEqual(ctx.exception.code, "render-pair-no-action-object")

    def test_malformed_claim_refused(self):
        ao = ur.render_action_object(_fields())
        with self.assertRaises(ur.RenderPairError) as ctx:
            ur.check_render_pair(ao, ["raw string"])
        self.assertEqual(ctx.exception.code, "render-pair-claim-malformed")

    def test_tampered_claim_refused(self):
        import copy
        ao = ur.render_action_object(_fields())
        claim = ur.render_untrusted_claim("real", max_chars=50,
                                          source_label="s")
        tampered = copy.copy(claim)
        object.__setattr__(tampered, "capped_text", "fake")
        with self.assertRaises(ur.RenderPairError) as ctx:
            ur.check_render_pair(ao, [tampered])
        self.assertEqual(ctx.exception.code, "render-pair-claim-tampered")

    def test_tampered_action_object_refused(self):
        import copy
        ao = ur.render_action_object(_fields())
        tampered = copy.copy(ao)
        object.__setattr__(tampered, "action", "delete_all")
        with self.assertRaises(ur.RenderPairError) as ctx:
            ur.check_render_pair(tampered, [])
        self.assertEqual(ctx.exception.code,
                         "render-pair-action-object-tampered")

    def test_non_list_claims_is_type_error(self):
        ao = ur.render_action_object(_fields())
        with self.assertRaises(TypeError):
            ur.check_render_pair(ao, "notalist")

    def test_refused_constant_exists(self):
        self.assertEqual(ur.RENDER_PAIR_REFUSED, "render-pair-refused")


if __name__ == "__main__":
    unittest.main()
