"""Unit tests for gov/packet_display.py — F192 (wave-175) closure.

The shared display schema both approver surfaces consume. Tests here
pin the normalizer and row shapes; the public-seam behavior (what the
approver actually sees) is covered by
evals/f192_carrier_visibility_battery.py.
"""
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from gov import packet_display  # noqa: E402


def _pkt(prov=None, att=None):
    pkt = {}
    if prov is not None:
        pkt["memory_provenance"] = prov
    if att is not None:
        pkt["attachment_carriers"] = att
    return pkt


class TestNormalizeCarrier(unittest.TestCase):
    def test_none_is_explicit_sentinel(self):
        self.assertEqual(packet_display.normalize_carrier(None),
                         packet_display.CARRIER_NONE)

    def test_blank_is_explicit_sentinel(self):
        self.assertEqual(packet_display.normalize_carrier("   "),
                         packet_display.CARRIER_NONE)

    def test_value_passes_through(self):
        self.assertEqual(packet_display.normalize_carrier("wav"), "wav")

    def test_non_string_str(self):
        self.assertEqual(packet_display.normalize_carrier(7), "7")

    def test_never_raises(self):
        class Bad:
            def __str__(self):
                raise RuntimeError("nope")
        self.assertEqual(packet_display.normalize_carrier(Bad()),
                         packet_display.CARRIER_NONE)


class TestProvenanceDisplayItems(unittest.TestCase):
    def test_items_keep_all_fields(self):
        items = packet_display.provenance_display_items(_pkt(
            prov=[{"mem_key": "k", "principal": "p",
                   "provenance_class": "un_elevated", "detail": "d",
                   "input_carrier": "wav"}]))
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["input_carrier"], "wav")
        self.assertEqual(items[0]["principal"], "p")

    def test_missing_fields_degrade_explicitly(self):
        items = packet_display.provenance_display_items(_pkt(prov=[{}]))
        self.assertIn("unknown", items[0]["mem_key"])

    def test_non_dict_items_skipped(self):
        items = packet_display.provenance_display_items(
            _pkt(prov=["x", 42, None]))
        self.assertEqual(items, [])

    def test_non_packet_ok(self):
        self.assertEqual(packet_display.provenance_display_items(None), [])


class TestFormatMemoryProvenance(unittest.TestCase):
    def test_carrier_always_named(self):
        text = packet_display.format_memory_provenance(_pkt(
            prov=[{"mem_key": "memory/voicememo.md", "detail": "d",
                   "input_carrier": "wav"},
                  {"mem_key": "memory/clean.md", "detail": "d2"}]))
        self.assertIn("wav", text)
        self.assertIn(packet_display.CARRIER_NONE, text)

    def test_empty_is_explicit(self):
        text = packet_display.format_memory_provenance(_pkt(prov=[]))
        self.assertIn("none disclosed", text)


class TestFormatAttachmentCarriers(unittest.TestCase):
    def test_lists_carriers(self):
        text = packet_display.format_attachment_carriers(
            _pkt(att=["mp3", "wav"]))
        self.assertIn("mp3", text)
        self.assertIn("wav", text)

    def test_dedupes(self):
        text = packet_display.format_attachment_carriers(
            _pkt(att=["mp3", "mp3"]))
        self.assertEqual(text, "mp3")

    def test_empty_is_explicit(self):
        self.assertEqual(
            packet_display.format_attachment_carriers(_pkt(att=[])),
            packet_display.CARRIER_NONE)

    def test_filters_junk(self):
        text = packet_display.format_attachment_carriers(
            _pkt(att=[None, "  ", "ogg"]))
        self.assertEqual(text, "ogg")


if __name__ == "__main__":
    unittest.main()
