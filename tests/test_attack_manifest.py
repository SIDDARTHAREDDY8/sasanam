"""Unit tests for gov.attack_manifest (wave-284 lane 4, nuclei STEAL).

Red-first: these pin the public-seam contracts of the attack-manifest
DSL -- template skeleton, matcher semantics, extractor chaining, the
-tc selection grammar, and the unsigned-template trust posture.
"""

import json
import os
import tempfile
import unittest

# Wave-95 lesson: module-level staging default.
os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import attack_manifest as am
from gov import attack_ledger as al
from gov import ed25519 as ed


def _good(**kw):
    t = {
        "id": "ssh-weak-cipher",
        "version": "1.0.0",
        "info": {
            "name": "SSH weak cipher offered",
            "author": ["red-team"],
            "severity": "high",
            "description": "server offers a weak cipher",
            "reference": ["https://example.invalid/ref"],
            "tags": ["ssh", "crypto"],
            "protocol": "ssh",
            "metadata": {"protocol": "ssh"},
        },
        "matchers": [
            {"type": "word", "words": ["3des"], "case-insensitive": True},
        ],
        "extractors": [],
    }
    t.update(kw)
    return t


def _seg(sid, obs, verdict="HELD"):
    return {"segment_id": sid, "observation": bytes(obs), "verdict": verdict}


class TestSeverityTaxonomy(unittest.TestCase):
    def test_pinned_five_levels(self):
        self.assertEqual(tuple(am.SEVERITIES),
                         ("info", "low", "medium", "high", "critical"))


class TestTemplateValidation(unittest.TestCase):
    def test_valid_template_normalizes(self):
        norm = am.validate_template(_good())
        self.assertEqual(norm["id"], "ssh-weak-cipher")
        self.assertEqual(norm["version"], "1.0.0")
        self.assertEqual(norm["info"]["severity"], "high")
        self.assertEqual(norm["matchers-condition"], "or")
        self.assertEqual(norm["matcher_types"], ["word"])
        self.assertEqual(norm["extractor_types"], [])

    def test_defaults(self):
        norm = am.validate_template(_good(extractors=[
            {"type": "regex", "name": "c", "pattern": r"(x)"}]))
        self.assertEqual(norm["extractors"][0]["group"], 0)
        self.assertFalse(norm["matchers"][0]["negative"])

    def test_bad_id(self):
        with self.assertRaises(am.TemplateMalformed) as cm:
            am.validate_template(_good(id="BAD ID"))
        self.assertEqual(cm.exception.code, "manifest-template-malformed")

    def test_bad_version(self):
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(version="1.0"))

    def test_bad_severity(self):
        info = dict(_good()["info"], severity="severe")
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(info=info))

    def test_empty_matchers(self):
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(matchers=[]))

    def test_unknown_matcher_type(self):
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(matchers=[{"type": "xpath"}]))

    def test_bad_regex_refused_at_load(self):
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(matchers=[
                {"type": "regex", "pattern": "(unclosed"}]))

    def test_bad_binary_hex_refused_at_load(self):
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(matchers=[
                {"type": "binary", "signature": "xyz"}]))

    def test_hostile_dsl_refused_at_load(self):
        for evil in ('__import__("os").system("x")',
                     'open("/etc/passwd").read()',
                     'len(observation'):
            with self.assertRaises(am.TemplateMalformed):
                am.validate_template(_good(matchers=[
                    {"type": "dsl", "expr": evil}]))

    def test_bad_extractor_group(self):
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(extractors=[
                {"type": "regex", "name": "c", "pattern": r"(x)", "group": 5}]))

    def test_template_digest_stable(self):
        a = am.template_digest(am.validate_template(_good()))
        b = am.template_digest(am.validate_template(_good()))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_error_is_valueerror_family(self):
        self.assertTrue(issubclass(am.TemplateMalformed, ValueError))


class TestMatchers(unittest.TestCase):
    def test_word_case_insensitive(self):
        norm = am.validate_template(_good())
        rec = am.run_template(norm, [_seg("s1", b"CIPHER 3DES ok")],
                              target="isolated")
        self.assertTrue(rec["per_segment"][0]["fired"])

    def test_word_case_sensitive_miss(self):
        norm = am.validate_template(_good(matchers=[
            {"type": "word", "words": ["3des"]}]))
        rec = am.run_template(norm, [_seg("s1", b"CIPHER 3DES ok")],
                              target="isolated")
        self.assertFalse(rec["per_segment"][0]["fired"])

    def test_negative_inverts(self):
        norm = am.validate_template(_good(matchers=[
            {"type": "word", "words": ["clean"], "negative": True}]))
        rec = am.run_template(norm, [_seg("s1", b"dirty input")],
                              target="isolated")
        self.assertTrue(rec["per_segment"][0]["fired"])

    def test_matchers_condition_and(self):
        norm = am.validate_template(_good(
            matchers=[
                {"type": "word", "words": ["aaa"]},
                {"type": "word", "words": ["bbb"]},
            ],
            **{"matchers-condition": "and"}))
        rec = am.run_template(norm, [_seg("s1", b"aaa only")],
                              target="isolated")
        self.assertFalse(rec["per_segment"][0]["fired"])
        rec = am.run_template(norm, [_seg("s1", b"aaa bbb")],
                              target="isolated")
        self.assertTrue(rec["per_segment"][0]["fired"])

    def test_binary_with_offset(self):
        norm = am.validate_template(_good(matchers=[
            {"type": "binary", "signature": "dead", "offset": 2}]))
        rec = am.run_template(norm, [_seg("s1", b"\x00\x00\xde\xad")],
                              target="isolated")
        self.assertTrue(rec["per_segment"][0]["fired"])
        rec = am.run_template(norm, [_seg("s1", b"\xde\xad\x00\x00")],
                              target="isolated")
        self.assertFalse(rec["per_segment"][0]["fired"])

    def test_dsl_type_mismatch_does_not_fire(self):
        # verdict is a str; comparing it numerically is a type error
        # -> the matcher fails closed (no fire), never crashes.
        norm = am.validate_template(_good(matchers=[
            {"type": "dsl", "expr": 'verdict > 3'}]))
        rec = am.run_template(norm, [_seg("s1", b"3des", "BREAK")],
                              target="isolated")
        self.assertFalse(rec["per_segment"][0]["fired"])

    def test_segment_part(self):
        norm = am.validate_template(_good(matchers=[
            {"type": "word", "words": ["s9"], "part": "segment_id"}]))
        rec = am.run_template(norm, [_seg("s9", b"nothing here")],
                              target="isolated")
        self.assertTrue(rec["per_segment"][0]["fired"])

    def test_bad_segment_shape(self):
        norm = am.validate_template(_good())
        with self.assertRaises(am.TemplateMalformed):
            am.run_template(norm, [{"segment_id": "s",
                                    "observation": "not-bytes"}],
                            target="isolated")

    def test_bad_target(self):
        norm = am.validate_template(_good())
        with self.assertRaises(am.TemplateMalformed):
            am.run_template(norm, [], target="staging")


class TestExtractors(unittest.TestCase):
    def test_regex_group(self):
        norm = am.validate_template(_good(
            matchers=[{"type": "word", "words": ["cipher"]}],
            extractors=[{"type": "regex", "name": "c",
                         "pattern": r"cipher: (\S+)", "group": 1}]))
        rec = am.run_template(norm, [_seg("s1", b"cipher: 3des")],
                              target="isolated")
        self.assertEqual(rec["extracted"], {"c": ["3des"]})

    def test_extractors_only_on_fired(self):
        norm = am.validate_template(_good(
            matchers=[{"type": "word", "words": ["nomatch"]}],
            extractors=[{"type": "regex", "name": "c",
                         "pattern": r"cipher: (\S+)", "group": 1}]))
        rec = am.run_template(norm, [_seg("s1", b"cipher: 3des")],
                              target="isolated")
        self.assertEqual(rec["extracted"], {})

    def test_dsl_extractor(self):
        norm = am.validate_template(_good(
            matchers=[{"type": "word", "words": ["x"]}],
            extractors=[{"type": "dsl", "name": "v",
                         "expr": 'verdict == "BREAK"'}]))
        rec = am.run_template(norm, [_seg("s1", b"x", "BREAK")],
                              target="isolated")
        self.assertEqual(rec["extracted"], {"v": ["True"]})


class TestSelection(unittest.TestCase):
    def _two(self):
        a = am.validate_template(_good())
        b = am.validate_template(_good(
            id="http-banner-leak", version="2.1.0",
            info=dict(_good()["info"], severity="low",
                      tags=["http", "disclosure"],
                      metadata={"protocol": "http"})))
        return [a, b]

    def test_id_select(self):
        got = am.select(self._two(), "id == 'http-banner-leak'")
        self.assertEqual([t["id"] for t in got], ["http-banner-leak"])

    def test_severity_neq(self):
        got = am.select(self._two(), "severity != 'high'")
        self.assertEqual([t["id"] for t in got], ["http-banner-leak"])

    def test_in_tags(self):
        got = am.select(self._two(), "'http' in tags")
        self.assertEqual([t["id"] for t in got], ["http-banner-leak"])

    def test_metadata(self):
        got = am.select(self._two(), "metadata.protocol == 'http'")
        self.assertEqual([t["id"] for t in got], ["http-banner-leak"])

    def test_composition(self):
        got = am.select(
            self._two(),
            "(severity == 'high' && 'ssh' in tags) || id == 'http-banner-leak'")
        self.assertEqual(sorted(t["id"] for t in got),
                         ["http-banner-leak", "ssh-weak-cipher"])

    def test_unknown_field_refused(self):
        with self.assertRaises(am.SelectionInvalid) as cm:
            am.select(self._two(), "nosuchfield == 'x'")
        self.assertEqual(cm.exception.code, "manifest-selection-invalid")

    def test_truncated_expression_refused(self):
        with self.assertRaises(am.SelectionInvalid):
            am.select(self._two(), "severity ==")

    def test_protocol_first_class(self):
        a = am.validate_template(_good())
        info = dict(_good()["info"], protocol=None)
        c = am.validate_template(_good(id="no-proto", info=info))
        got = am.select([a, c], "protocol == 'ssh'")
        self.assertEqual([t["id"] for t in got], ["ssh-weak-cipher"])

    def test_version_select(self):
        a = am.validate_template(_good())
        b = am.validate_template(_good(id="other", version="2.0.0"))
        got = am.select([a, b], "version == '2.0.0'")
        self.assertEqual([t["id"] for t in got], ["other"])

    def test_bad_protocol_shape(self):
        info = dict(_good()["info"], protocol="SSH")
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(info=info))

    def test_deep_dsl_nesting_refused(self):
        deep = "(" * 5000 + 'contains("x")' + ")" * 5000
        with self.assertRaises(am.TemplateMalformed):
            am.validate_template(_good(matchers=[{"type": "dsl",
                                                  "expr": deep}]))

    def test_deep_selection_nesting_refused(self):
        a = am.validate_template(_good())
        with self.assertRaises(am.SelectionInvalid):
            am.select([a], "(" * 5000 + "severity == 'high'" + ")" * 5000)

    def test_bare_metadata_refused(self):
        a = am.validate_template(_good())
        with self.assertRaises(am.SelectionInvalid):
            am.select([a], "metadata == 'ssh'")


class TestTemplatesFromAtomics(unittest.TestCase):
    def test_derives_selectable_templates(self):
        tmpls = am.templates_from_atomics([
            {"name": "SSH Weak Cipher", "description": "d",
             "severity": "high"},
            {"name": "HTTP Banner", "description": "d"},
        ])
        self.assertEqual([t["id"] for t in tmpls],
                         ["ssh-weak-cipher", "http-banner"])
        self.assertEqual([t["info"]["severity"] for t in tmpls],
                         ["high", "info"])
        got = am.select(tmpls, "severity == 'high'")
        self.assertEqual([t["id"] for t in got], ["ssh-weak-cipher"])

    def test_break_matcher_fires(self):
        tmpls = am.templates_from_atomics(
            [{"name": "X", "description": "d"}])
        rec = am.run_template(
            tmpls[0],
            [{"segment_id": "s", "observation": b"z", "verdict": "BREAK"}],
            target="isolated")
        self.assertTrue(rec["fired"])

    def test_bad_severity_refused(self):
        with self.assertRaises(am.TemplateMalformed):
            am.templates_from_atomics(
                [{"name": "X", "description": "d", "severity": "severe"}])

    def test_bad_default_severity_refused(self):
        with self.assertRaises(am.TemplateMalformed):
            am.templates_from_atomics([], default_severity="severe")


class TestTrust(unittest.TestCase):
    def test_unsigned_isolated(self):
        norm = am.validate_template(_good())
        rec = am.run_template(norm, [_seg("s1", b"3des")], target="isolated")
        self.assertEqual(rec["trust"], "unsigned")
        self.assertFalse(rec["unsigned_optout"])

    def test_unsigned_production_refused(self):
        norm = am.validate_template(_good())
        with self.assertRaises(am.TemplateUnsigned) as cm:
            am.run_template(norm, [_seg("s1", b"3des")], target="production")
        self.assertEqual(cm.exception.code, "manifest-template-unsigned")

    def test_optout_recorded(self):
        norm = am.validate_template(_good())
        rec = am.run_template(norm, [_seg("s1", b"3des")],
                              target="production", allow_unsigned=True,
                              optout_reason="analyst override")
        self.assertTrue(rec["unsigned_optout"])
        self.assertEqual(rec["optout_reason"], "analyst override")

    def test_optout_reason_required(self):
        norm = am.validate_template(_good())
        with self.assertRaises(am.TemplateMalformed):
            am.run_template(norm, [_seg("s1", b"3des")],
                            target="production", allow_unsigned=True,
                            optout_reason="  ")

    def test_optout_at_isolated_is_malformed(self):
        norm = am.validate_template(_good())
        with self.assertRaises(am.TemplateMalformed):
            am.run_template(norm, [_seg("s1", b"3des")],
                            target="isolated", allow_unsigned=True,
                            optout_reason="x")


class TestSignVerify(unittest.TestCase):
    def test_roundtrip(self):
        norm = am.validate_template(_good())
        seed = ed.generate_seed()
        env = am.sign_template(seed, norm)
        # Wave-243: verify-style contracts return exact True.
        self.assertIs(am.verify_signed_template(env), True)

    def test_tamper_fails_loud(self):
        norm = am.validate_template(_good())
        seed = ed.generate_seed()
        env = am.sign_template(seed, norm)
        env["template"]["info"]["severity"] = "critical"
        with self.assertRaises(am.SignatureInvalid) as cm:
            am.verify_signed_template(env)
        self.assertEqual(cm.exception.code, "manifest-signature-invalid")

    def test_wrong_pubkey_fails(self):
        norm = am.validate_template(_good())
        seed = ed.generate_seed()
        env = am.sign_template(seed, norm)
        other_pub = ed.publickey(ed.generate_seed())
        with self.assertRaises(am.SignatureInvalid):
            am.run_signed_template(env, other_pub,
                                   [_seg("s1", b"3des")], target="production")

    def test_signed_runs_at_production(self):
        norm = am.validate_template(_good())
        seed = ed.generate_seed()
        pub = ed.publickey(seed)
        env = am.sign_template(seed, norm)
        rec = am.run_signed_template(env, pub, [_seg("s1", b"3des")],
                                     target="production")
        self.assertEqual(rec["trust"], "signed")
        self.assertTrue(rec["fired"])

    def test_bad_envelope_shape(self):
        with self.assertRaises(am.SignatureInvalid):
            am.verify_signed_template({"nope": True})


class TestLedgerBinding(unittest.TestCase):
    def test_bind_records_piece_and_score(self):
        d = tempfile.mkdtemp(prefix="nuc-ut-")
        ledger = al.AttackLedger(os.path.join(d, "l.db"))
        try:
            norm = am.validate_template(_good())
            rec = am.run_template(norm, [_seg("s1", b"3des", "BREAK")],
                                  target="isolated")
            bound = am.bind_template_run(ledger, norm, rec)
            self.assertTrue(bound["piece_id"])
            self.assertTrue(bound["score_id"])
            self.assertTrue(ledger.verify_chain())
        finally:
            ledger.close()

    def test_bind_wrong_record_refused(self):
        d = tempfile.mkdtemp(prefix="nuc-ut-")
        ledger = al.AttackLedger(os.path.join(d, "l.db"))
        try:
            norm = am.validate_template(_good())
            with self.assertRaises(am.TemplateMalformed):
                am.bind_template_run(ledger, norm, {"template_id": "other"})
        finally:
            ledger.close()


if __name__ == "__main__":
    unittest.main()
