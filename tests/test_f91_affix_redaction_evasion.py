"""F91 regression: affixed-secret redaction evasion (AGT `_old`-suffix class).

AGT's redactor was bypassed by secrets carrying affixes like ``_old``.
Probed against our DLP (gov/dlp.py), two genuine bypasses were found and
fixed; the credential block-list half was verified robust:

* PII redaction (scrub_pii): SSN / phone / card patterns used ``\\b``
  word boundaries, so ``123-45-6789_old``, ``old_123-45-6789``,
  ``4111111111111111_backup`` and ``555-123-4567x2`` leaked into
  logs/approvals in cleartext. Fixed: digit-only boundaries
  (``(?<![0-9])``/``(?![0-9])``) -- affixed word-chars no longer
  suppress the match; longer digit runs still do not match.
* Entropy tripwire: affixed keywords (``password_old``,
  ``old_password``, ``api_key_backup``) defeated the keyword ``\\b``
  and slipped past the tripwire next to high-entropy tokens. Fixed:
  letter-only boundaries -- ``monkey``/``keyboard`` still do not trip.

Verified NOT vulnerable (documented, no finding): credential regexes
are unanchored searches, so ``ghp_..._old`` / ``sk_live_..._backup`` /
``AKIA..._old`` still block; ``AKIA_old<16>`` (infix) does not match
but is not a valid credential shape either (would not authenticate).

Each bypass test below FAILS on the pre-fix DLP (value leaks / no
tripwire) and passes after.
"""

import os
import sys
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from gov import dlp  # noqa: E402

_TOKEN = "zHx9Q2vNmP4kR7tW8yU5bN3mK6jL"  # high-entropy tripwire bait


class TestF91AffixedPiiIsRedacted(unittest.TestCase):
    def _assert_redacted(self, text, rule_id, sensitive):
        redacted, hits = dlp.scrub_pii(text)
        self.assertIn(rule_id, hits,
                      "F91: affixed PII leaked in cleartext: %r -> %r"
                      % (text, redacted))
        self.assertNotIn(sensitive, redacted,
                         "F91: sensitive digits survived redaction: %r"
                         % (redacted,))

    def test_ssn_suffix_affixes_redacted(self):
        for affix in ("_old", "_backup", "_1", "-copy"):
            self._assert_redacted("ssn 123-45-6789%s end" % affix,
                                 "pii-ssn", "123-45-6789")

    def test_ssn_prefix_affixes_redacted(self):
        for affix in ("old_", "prev_", "x"):
            self._assert_redacted("ssn %s123-45-6789 end" % affix,
                                 "pii-ssn", "123-45-6789")

    def test_phone_affixes_redacted(self):
        for text in ("call 555-123-4567_old", "call 555-123-4567x2",
                     "call old_555-123-4567"):
            self._assert_redacted(text, "pii-phone", "555-123-4567")

    def test_card_affixes_redacted(self):
        for text in ("card 4111111111111111_old",
                     "card 4111111111111111_backup",
                     "card 4111 1111 1111 1111_1"):
            self._assert_redacted(text, "pii-card", "4111111111111111")

    def test_affix_text_outside_marker_preserved(self):
        """The affix itself is harmless metadata; only the sensitive
        core is replaced."""
        redacted, _ = dlp.scrub_pii("ssn 123-45-6789_old")
        self.assertEqual(redacted, "ssn [REDACTED:pii-ssn]_old")

    def test_longer_digit_runs_still_not_redacted(self):
        """A longer numeric run is not an SSN/phone/card; the digit
        boundary must still suppress the match (no over-redaction)."""
        for text, rule in (("id 123-45-67890", "pii-ssn"),
                           ("call 555-123-45678", "pii-phone"),
                           ("ref 1234123-45-6789", "pii-ssn")):
            redacted, hits = dlp.scrub_pii(text)
            self.assertNotIn(rule, hits,
                             "F91: over-redacted a longer numeric run: %r"
                             % (text,))

    def test_email_affixes_still_redacted(self):
        for text in ("mail user@example.com_old", "mail old_user@example.com"):
            redacted, hits = dlp.scrub_pii(text)
            self.assertIn("pii-email", hits, text)
            self.assertNotIn("user@example.com", redacted, text)


class TestF91AffixedTripwireKeywords(unittest.TestCase):
    def _wire(self, keyword):
        return dlp.find_credential("deploy %s: %s" % (keyword, _TOKEN))

    def test_affixed_keywords_trip(self):
        for kw in ("password_old", "old_password", "api_key_backup",
                   "secret_1", "old_secret", "token2", "key_old"):
            self.assertEqual(self._wire(kw), "dlp-entropy-tripwire",
                             "F91: affixed keyword evaded the tripwire: %r"
                             % (kw,))

    def test_plain_keywords_still_trip(self):
        for kw in ("password", "api_key", "secret"):
            self.assertEqual(self._wire(kw), "dlp-entropy-tripwire", kw)

    def test_innocent_words_still_clean(self):
        """Letter-adjacent keywords must not trip: 'monkey'/'keyboard'
        guard against false positives (pre-existing pin)."""
        self.assertIsNone(dlp.find_credential("the monkey: " + _TOKEN))
        self.assertIsNone(dlp.find_credential("keyboard shortcut: " + _TOKEN))


class TestF91CredentialBlockSideRobust(unittest.TestCase):
    """Documents the probe result: the block-list half was NOT
    vulnerable to affixes (unanchored regex search)."""

    def test_affixed_known_format_secrets_still_block(self):
        cases = {
            "token ghp_abcdefghij1234567890_old": "dlp-github-token",
            "token old_ghp_abcdefghij1234567890": "dlp-github-token",
            "key sk_live_abcdefghijklmnop_backup": "dlp-stripe-live-key",
            "key AKIAABCDEFGHIJKLMNOP_old": "dlp-aws-access-key",
        }
        for text, rule in cases.items():
            self.assertEqual(dlp.find_credential(text), rule, text)

    def test_scan_tool_args_blocks_affixed_secret(self):
        blocked, rule, redacted, _ = dlp.scan_tool_args(
            "http_post",
            {"url": "https://x.example",
             "payload": "key=sk_live_abcdefghijklmnop_old"})
        self.assertTrue(blocked)
        self.assertEqual(rule, "dlp-stripe-live-key")
        self.assertNotIn("sk_live_abcdefghijklmnop_old",
                         str(redacted))


if __name__ == "__main__":
    unittest.main()
