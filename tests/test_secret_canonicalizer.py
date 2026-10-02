"""Unit tests for gov/secret_canonicalizer.py (wave-283, gitleaks STEAL).

The red-first contract battery lives at evals/w283_gitleaks_probes.py;
these are the white-box unit pins: rule construction fail-closed,
finding structure, decode/composite semantics, registry lifecycle,
and streaming offsets.
"""

import os
import re
import tempfile
import time
import unittest

from gov import secret_canonicalizer as sc


class RuleContractTest(unittest.TestCase):
    def test_ruleset_is_pinned_and_nonempty(self):
        self.assertTrue(sc.RULES)
        self.assertIsInstance(sc.RULESET_PIN, str)
        self.assertIn("2026-10-02", sc.RULESET_PIN)

    def test_rule_ids_unique(self):
        ids = [r.id for r in sc.RULES]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_rule_has_secret_group(self):
        for rule in sc.RULES:
            self.assertIn("secret", rule.pattern.groupindex,
                          "rule %s missing secretGroup" % rule.id)

    def test_fail_closed_bad_regex(self):
        with self.assertRaises(sc.RuleError):
            sc.compile_rules([{"id": "x", "kind": "k",
                               "regex": "(?P<secret>(unclosed",
                               "keywords": ("x",)}])

    def test_fail_closed_missing_secret_group(self):
        with self.assertRaises(sc.RuleError):
            sc.compile_rules([{"id": "x", "kind": "k",
                               "regex": r"password=(\S+)",
                               "keywords": ("password",)}])

    def test_fail_closed_duplicate_id(self):
        good = {"id": "x", "kind": "k", "regex": r"(?P<secret>abc\d+)",
                "keywords": ("abc",)}
        with self.assertRaises(sc.RuleError):
            sc.compile_rules([good, dict(good)])

    def test_fail_closed_unknown_key(self):
        with self.assertRaises(sc.RuleError):
            sc.compile_rules([{"id": "x", "kind": "k",
                               "regex": r"(?P<secret>abc)", "keywords": (),
                               "tags": (), "entropy_min": None,
                               "bogus": 1}])

    def test_fail_closed_empty_set(self):
        with self.assertRaises(sc.RuleError):
            sc.compile_rules([])

    def test_get_rule_unknown_refuses(self):
        with self.assertRaises(sc.RuleError):
            sc.get_rule("no-such-rule")

    def test_get_rule_roundtrip(self):
        rule = sc.get_rule("aws-access-key")
        self.assertEqual(rule.id, "aws-access-key")


class ScanTest(unittest.TestCase):
    def test_aws_key(self):
        fs = sc.scan("the key is AKIAIOSFODNN7EXAMPLE here")
        self.assertEqual(len(fs), 1)
        f = fs[0]
        self.assertEqual(f.detector, "aws-access-key")
        self.assertEqual(f.kind, "aws-access-key")
        self.assertEqual(f.secret_digest,
                         sc._secret_digest("AKIAIOSFODNN7EXAMPLE"))
        self.assertEqual(f.offset, 11)
        self.assertEqual(f.length, 20)

    def test_github_pat(self):
        fs = sc.scan("token ghp_" + "a" * 36 + " end")
        self.assertEqual([f.detector for f in fs], ["github-pat"])

    def test_private_key_block(self):
        pem = ("-----BEGIN RSA PRIVATE KEY-----\nMIIBPAIBAAJ\n"
               "-----END RSA PRIVATE KEY-----")
        fs = sc.scan(pem)
        self.assertEqual([f.kind for f in fs], ["private-key"])
        self.assertEqual(fs[0].length, len(pem))

    def test_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c"
        self.assertTrue(sc.credential_material_present("bearer jwt " + jwt))

    def test_no_raw_bytes_in_finding_or_repr(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        (f,) = sc.scan("x " + secret)
        blob = repr(f) + f.fingerprint + f.secret_digest
        self.assertNotIn(secret, blob)
        self.assertNotIn(secret, repr(f.to_dict()))

    def test_base64_evasion(self):
        import base64
        enc = base64.b64encode(b"password= hunter2-hunter2-x9").decode()
        fs = sc.scan("config blob " + enc)
        self.assertTrue(fs, "base64 layer not scanned")
        self.assertEqual(fs[0].encoding, "base64")

    def test_hex_evasion(self):
        enc = b"api_key=x9fK2mQ8vL4nR7tW1z".hex()
        fs = sc.scan("data " + enc)
        self.assertTrue(fs, "hex layer not scanned")
        self.assertEqual(fs[0].encoding, "hex")

    def test_percent_evasion(self):
        pct = "secret%3Dhunter2-hunter2-x9"
        fs = sc.scan("q=" + pct)
        self.assertTrue(fs, "percent layer not scanned")
        self.assertEqual(fs[0].encoding, "percent")

    def test_non_printable_decode_skipped(self):
        raw = bytes(range(1, 60)).hex()
        fs = sc.scan("data " + raw)
        self.assertFalse(any(f.encoding == "hex" for f in fs))

    def test_composite_near_fires_far_silent(self):
        near = "password: see value x9fK2mQ8vL4nR7tW1z0"
        far = "password: nothing here " + "x" * 600 + " x9fK2mQ8vL4nR7tW1z0"
        near_fs = [f for f in sc.scan(near)
                   if f.detector == "composite-keyword-entropy"]
        far_fs = [f for f in sc.scan(far)
                  if f.detector == "composite-keyword-entropy"]
        self.assertTrue(near_fs)
        self.assertFalse(far_fs)

    def test_anti_fp_uuid_and_policy_text(self):
        self.assertFalse(sc.credential_material_present(
            "id 550e8400-e29b-41d4-a716-446655440000 assigned"))
        self.assertFalse(sc.credential_material_present(
            "the password policy requires 12 characters"))
        self.assertFalse(sc.credential_material_present("api_key="))

    def test_overlap_dedupe(self):
        fs = sc.scan("api_key=hunter2-hunter2-x9 rejected")
        # composite + generic-api-key both match the same token span:
        # exactly one surviving finding per span.
        spans = {(f.offset, f.length) for f in fs}
        self.assertEqual(len(spans), len(fs))

    def test_sanitize_marks_redaction(self):
        text, fs = sc.sanitize("password= hunter2-hunter2-x9 ok")
        self.assertIn("[REDACTED:", text)
        self.assertNotIn("hunter2", text)
        self.assertTrue(fs)

    def test_sanitize_clean_verbatim(self):
        text, fs = sc.sanitize("nothing to see here")
        self.assertEqual(text, "nothing to see here")
        self.assertEqual(fs, ())

    def test_sanitize_decode_layer_redacts_encoded_span(self):
        import base64
        b64 = base64.b64encode(b"password=hunter2-hunter2-x9").decode()
        text = "blob: " + b64
        sanitized, fs = sc.sanitize(text)
        self.assertTrue(any(f.encoding for f in fs))
        self.assertEqual(sanitized, "blob: [REDACTED:password]")
        self.assertNotIn(b64, sanitized)

    def test_sanitize_decode_layer_no_decodable_fragment(self):
        import base64
        b64 = base64.b64encode(b"password=hunter2-hunter2-x9").decode()
        sanitized, _ = sc.sanitize("blob: " + b64)
        for frag in re.findall(r"[A-Za-z0-9+/]{8,}={0,2}", sanitized):
            try:
                dec = base64.b64decode(frag, validate=True)
            except Exception:
                continue
            self.assertNotIn(b"hunter2", dec)
            self.assertNotIn(b"password", dec)

    def test_base64_suffix_retry_against_merged_run(self):
        import base64
        b64 = base64.b64encode(b"password=hunter2hunter2x9").decode()
        text = "x" * 400 + b64
        fs = sc.scan(text)
        self.assertTrue(any(f.encoding == "base64" for f in fs),
                        "merged base64-alphabet run defeated the decode layer")

    def test_finding_carries_tags(self):
        (f,) = sc.scan("key AKIAIOSFODNN7EXAMPLE")
        self.assertIn("aws", f.tags)
        self.assertIn("aws", f.to_dict()["tags"])


class RegistryTest(unittest.TestCase):
    def test_register_is_allowed_suppress(self):
        reg = sc.ExceptionRegistry()
        (f,) = sc.scan("password= hunter2-hunter2-x9")
        audit = reg.register(fingerprint=f.fingerprint, reason="test fixture",
                             approver="lane-4")
        self.assertEqual(audit["event"], "secret-exception-registered")
        self.assertTrue(reg.is_allowed(f.fingerprint))
        kept, suppressed = reg.suppress((f,))
        self.assertEqual(kept, ())
        self.assertEqual(suppressed, (f,))

    def test_expiry_enforced(self):
        reg = sc.ExceptionRegistry()
        (f,) = sc.scan("password= hunter2-hunter2-x9")
        reg.register(fingerprint=f.fingerprint, reason="old",
                     approver="lane-4", expires_at=time.time() - 1)
        self.assertFalse(reg.is_allowed(f.fingerprint))

    def test_register_refuses_bad_fingerprint(self):
        reg = sc.ExceptionRegistry()
        with self.assertRaises(sc.RuleError):
            reg.register(fingerprint="not-hex", reason="x", approver="y")

    def test_save_load_roundtrip(self):
        reg = sc.ExceptionRegistry()
        (f,) = sc.scan("password= hunter2-hunter2-x9")
        reg.register(fingerprint=f.fingerprint, reason="persist",
                     approver="lane-4")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "registry.json")
            reg.save(path)
            reg2 = sc.ExceptionRegistry.load(path)
            self.assertTrue(reg2.is_allowed(f.fingerprint))

    def test_load_refuses_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bad.json")
            with open(path, "w") as fh:
                fh.write('{"nope": 1}')
            with self.assertRaises(sc.RuleError):
                sc.ExceptionRegistry.load(path)

    def test_load_refuses_pin_mismatch(self):
        reg = sc.ExceptionRegistry()
        (f,) = sc.scan("password= hunter2-hunter2-x9")
        reg.register(fingerprint=f.fingerprint, reason="x", approver="y")
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "registry.json")
            reg.save(path)
            with open(path) as fh:
                data = fh.read().replace(sc.RULESET_PIN, "other-pin")
            with open(path, "w") as fh:
                fh.write(data)
            with self.assertRaises(sc.RuleError):
                sc.ExceptionRegistry.load(path)


class StreamingTest(unittest.TestCase):
    def test_split_secret_caught_once_with_absolute_offset(self):
        secret = "AKIAIOSFODNN7EXAMPLE"
        text = "prefix " + secret + " suffix"
        scanner = sc.Scanner(location="stream")
        all_fs = []
        all_fs.extend(scanner.feed(text[:10]))       # "prefix AK"
        all_fs.extend(scanner.feed(text[10:20]))     # "IAIOSFODNN"
        all_fs.extend(scanner.feed(text[20:]))      # rest
        all_fs.extend(scanner.finish())
        self.assertEqual(len(all_fs), 1)
        self.assertEqual(all_fs[0].offset, 7)
        self.assertEqual(all_fs[0].length, 20)

    def test_scan_stream_helper(self):
        secret = "ghp_" + "b" * 36
        fs = sc.scan_stream(["x " + secret[:10], secret[10:] + " y"])
        self.assertEqual(len(fs), 1)
        self.assertEqual(fs[0].offset, 2)


if __name__ == "__main__":
    unittest.main()
