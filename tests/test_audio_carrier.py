#!/usr/bin/env python3
"""Unit tests for gov/audio_carrier.py (F191, wave-174).

Synthetic carriers only ($0, no audio model, no network). Deterministic.
"""

import base64
import os
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (REPO_ROOT, os.path.join(REPO_ROOT, "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402

provision_test_key()

from gov import audio_carrier  # noqa: E402
from gov.memory_inbox import MemoryInbox  # noqa: E402
from gov.memory_provenance import MemoryFirewall  # noqa: E402

WAV = (b"RIFF" + b"\x54\x00\x00\x00" + b"WAVE" + b"fmt " +
       b"\x10\x00\x00\x00" + b"\x01\x00\x01\x00" +
       b"\x40\x1f\x00\x00" + b"\x40\x1f\x00\x00" +
       b"\x01\x00\x08\x00" + b"data" + b"\x30\x00\x00\x00" +
       b"\x80" * 0x30)
MP3 = b"ID3\x04\x00\x00\x00\x00\x00\x00" + b"\x00" * 32
MP3_FRAME = b"\xff\xfb\x90\x00" + b"\x00" * 32
OGG = b"OggS\x00\x02\x00\x00\x00\x00\x00\x00" + b"\x00" * 24
FLAC = b"fLaC\x00\x00\x00\x22" + b"\x00" * 32
TEXT = b"quarterly report: revenue grew 4% over the prior quarter."


class ClassifyTest(unittest.TestCase):
    def test_magic_cases(self):
        self.assertEqual(audio_carrier.classify_carrier(WAV), "wav")
        self.assertEqual(audio_carrier.classify_carrier(MP3), "mp3")
        self.assertEqual(audio_carrier.classify_carrier(OGG), "ogg")
        self.assertEqual(audio_carrier.classify_carrier(FLAC), "flac")
        # Raw MPEG frames without an ID3 tag are deliberately NOT
        # classified (the frame-sync heuristic false-positives on
        # padding bytes) -- documented residual.
        self.assertIsNone(audio_carrier.classify_carrier(MP3_FRAME))

    def test_non_audio(self):
        self.assertIsNone(audio_carrier.classify_carrier(TEXT))
        self.assertIsNone(audio_carrier.classify_carrier(b""))
        self.assertIsNone(audio_carrier.classify_carrier(None))
        self.assertIsNone(audio_carrier.classify_carrier("notes.txt"))
        self.assertIsNone(audio_carrier.classify_carrier(12345))

    def test_base64_wrap(self):
        self.assertEqual(
            audio_carrier.classify_carrier(base64.b64encode(WAV).decode()),
            "wav")
        # A filename alone is never a carrier -- bytes classify.
        self.assertIsNone(audio_carrier.classify_carrier("q3_memo.wav"))

    def test_never_raises(self):
        for junk in (b"\xff" * 100, "!!!not-base64!!!", "\x00" * 3,
                     object(), ["wav"], {"a": 1}):
            self.assertIsNone(audio_carrier.classify_carrier(junk))


class AttachmentScanTest(unittest.TestCase):
    def test_recognizes_attachment(self):
        args = {
            "note": "handle the attached voice memo",
            "attachment": base64.b64encode(WAV).decode(),
            "attachment_name": "q3_memo.wav",
        }
        self.assertEqual(
            audio_carrier.attachment_carriers(args), ["wav"])

    def test_clean_args(self):
        self.assertEqual(
            audio_carrier.attachment_carriers({"path": "notes.txt"}), [])
        self.assertEqual(audio_carrier.attachment_carriers({}), [])
        self.assertEqual(
            audio_carrier.attachment_carriers("not-a-dict"), [])

    def test_nested(self):
        args = {"files": [{"blob": base64.b64encode(OGG).decode()}]}
        self.assertEqual(
            audio_carrier.attachment_carriers(args), ["ogg"])


class ResolveTest(unittest.TestCase):
    def test_consistent(self):
        carrier, mismatch = audio_carrier.resolve_carrier(
            declared_mime="audio/wav", data=WAV)
        self.assertEqual(carrier, "wav")
        self.assertFalse(mismatch)

    def test_mislabeled_audio_as_text(self):
        carrier, mismatch = audio_carrier.resolve_carrier(
            declared_mime="text/plain", data=WAV)
        self.assertEqual(carrier, "wav")
        self.assertTrue(mismatch)

    def test_declared_audio_not_audio(self):
        carrier, mismatch = audio_carrier.resolve_carrier(
            declared_mime="audio/mpeg", data=TEXT)
        self.assertIsNone(carrier)
        self.assertTrue(mismatch)

    def test_filename_hint(self):
        _, mismatch = audio_carrier.resolve_carrier(
            declared_name="memo.wav", data=TEXT)
        self.assertTrue(mismatch)


class _FirewallMixin:
    def _firewall(self, inbox=None):
        tmp = tempfile.mkdtemp(prefix="f191-unit-")
        return MemoryFirewall(
            ledger_path=os.path.join(tmp, "mem.jsonl"), inbox=inbox)

    def _inbox(self):
        tmp = tempfile.mkdtemp(prefix="f191-unit-inbox-")
        return MemoryInbox(path=os.path.join(tmp, "inbox.jsonl"))


class WritePathTest(_FirewallMixin, unittest.TestCase):
    def test_marker_bound_and_mac(self):
        fw = self._firewall()
        record, tier, _ = audio_carrier.record_audio_derived_write(
            fw, "customer-org", "notes/memo.txt", "hello memo",
            writer_agent_id="agent-1", writer_run_id="run-1")
        self.assertEqual(record.get("input_carrier"), "audio")
        self.assertTrue(record.get("mac"))
        self.assertFalse(record.get("carrier_mismatch"))

    def test_native_kwarg_path(self):
        fw = self._firewall()
        record, tier, _ = fw.record_memory_write(
            "customer-org", "notes/memo2.txt", "hello again",
            writer_agent_id="agent-1", writer_run_id="run-1",
            read_fingerprints=(), tainted_run=False, carrier="wav")
        self.assertEqual(record.get("input_carrier"), "wav")

    def test_no_carrier_is_backward_compatible(self):
        fw = self._firewall()
        record, tier, _ = fw.record_memory_write(
            "customer-org", "notes/plain.txt", "plain note",
            writer_agent_id="agent-1", writer_run_id="run-1",
            read_fingerprints=(), tainted_run=False)
        self.assertIsNone(record.get("input_carrier"))
        self.assertFalse(record.get("carrier_mismatch"))

    def test_mismatch_forces_untrusted_and_inbox(self):
        inbox = self._inbox()
        fw = self._firewall(inbox=inbox)
        record, tier, reason = audio_carrier.record_audio_derived_write(
            fw, "customer-org", "notes/sneaky.txt",
            "declared transcript, actually audio bytes",
            writer_agent_id="agent-1", writer_run_id="run-1",
            carrier="wav", carrier_mismatch=True)
        self.assertEqual(tier, "untrusted_derived")
        self.assertTrue(record.get("carrier_mismatch"))
        self.assertIn("carrier_mismatch", reason)
        digest = record["content_sha256"]
        item = inbox.pending_for("customer-org", "notes/sneaky.txt",
                                 digest)
        self.assertIsNotNone(item)
        self.assertEqual(item["reason_class"], "carrier_mismatch")

    def test_banner_names_carrier(self):
        fw = self._firewall()
        content = "voice memo note about the quarterly report"
        fw.record_memory_write(
            "customer-org", "notes/memo3.txt", content,
            writer_agent_id="agent-1", writer_run_id="run-1",
            read_fingerprints=(), tainted_run=False, carrier="wav")
        banner = fw.provenance_banner("customer-org", "notes/memo3.txt",
                                      content)
        self.assertIsNotNone(banner)
        self.assertIn("AUDIO CARRIER", banner)
        self.assertIn("wav", banner)

    def test_no_banner_without_carrier(self):
        fw = self._firewall()
        content = "a perfectly ordinary text note"
        fw.record_memory_write(
            "customer-org", "notes/plain2.txt", content,
            writer_agent_id="agent-1", writer_run_id="run-1",
            read_fingerprints=(), tainted_run=False)
        self.assertIsNone(
            fw.provenance_banner("customer-org", "notes/plain2.txt",
                                 content))


class ActgateDisclosureTest(_FirewallMixin, unittest.TestCase):
    def test_carrier_rides_disclosure(self):
        from gov.memory_actgate import ActGate
        fw = self._firewall()
        content = "audio-derived fact, paraphrased"
        fw.record_memory_write(
            "customer-org", "notes/m4.txt", content,
            writer_agent_id="agent-1", writer_run_id="run-1",
            read_fingerprints=(), tainted_run=True, carrier="mp3")
        ag = ActGate(firewall=fw, trusted_principals=())
        ag.note_read("run-9", "customer-org", "notes/m4.txt", content)
        snap = ag.summarize("run-9")
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0]["input_carrier"], "mp3")

    def test_no_carrier_discloses_none(self):
        from gov.memory_actgate import ActGate
        fw = self._firewall()
        content = "plain text fact"
        fw.record_memory_write(
            "customer-org", "notes/m5.txt", content,
            writer_agent_id="agent-1", writer_run_id="run-1",
            read_fingerprints=(), tainted_run=False)
        ag = ActGate(firewall=fw, trusted_principals=())
        ag.note_read("run-9", "customer-org", "notes/m5.txt", content)
        snap = ag.summarize("run-9")
        # agent-clean reads are not tracked; if tracked, carrier is None.
        for entry in snap:
            if entry["mem_key"] == "notes/m5.txt":
                self.assertIsNone(entry["input_carrier"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
