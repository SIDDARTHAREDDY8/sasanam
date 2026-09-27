"""Unit tests for wave-140 cross-run destination history.

Covers gov/destination_ledger.py (persistence format round-trip,
TTL, sweep, purge, identity keying, tamper evidence, normalization
fail-closed, per-agent cap) and the RareTokenTracker wiring
(cross-run novelty, zero behavior change without a ledger).
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from gov.destination_ledger import (
    DestinationLedger, DestinationLedgerError,
    MAX_DESTINATIONS_PER_AGENT, MAX_DESTINATION_LENGTH,
)
from gov import rare_token as rt

AGENT = "agent-dl-a"
OTHER = "agent-dl-b"
DEST = "https://vendor.synthetic.local/sync"


def _path():
    d = tempfile.mkdtemp(prefix="govdl-unit-")
    return os.path.join(d, "dest.jsonl")


class PersistenceTest(unittest.TestCase):
    def test_round_trip(self):
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        led2 = DestinationLedger(p)
        self.assertTrue(led2.known(AGENT, DEST))
        self.assertEqual(led2.destinations_for(AGENT), [DEST])

    def test_empty_file_refused(self):
        p = _path()
        open(p, "w").close()
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_corrupt_line_refused(self):
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write("not json{{{\n")
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_dropped_record_refused(self):
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        led.record(AGENT, DEST + "/2")
        lines = open(p, encoding="utf-8").read().splitlines()
        # Drop the first destination record (keep header/footer).
        kept = [lines[0]] + [ln for ln in lines[1:-1]
                             if DEST + "/2" in ln] + [lines[-1]]
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(kept) + "\n")
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_footer_strip_refused(self):
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        lines = open(p, encoding="utf-8").read().splitlines()
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines[:-1]) + "\n")
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_footer_chain_tip_tamper_refused(self):
        # Wave-140 audit fix: the footer must be validated on load.
        # Rewriting chain_tip without recomputing is refused.
        import json as _json
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        lines = open(p, encoding="utf-8").read().splitlines()
        footer = _json.loads(lines[-1])
        footer["chain_tip"] = "0" * 64
        lines[-1] = _json.dumps(footer, sort_keys=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_footer_file_digest_tamper_refused(self):
        # Rewriting file_digest without recomputing is refused.
        import json as _json
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        lines = open(p, encoding="utf-8").read().splitlines()
        footer = _json.loads(lines[-1])
        footer["file_digest"] = "0" * 64
        lines[-1] = _json.dumps(footer, sort_keys=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_naive_truncation_refused(self):
        # Drop the last record but keep the old footer: the footer
        # no longer matches the file, so the load fails closed. (A
        # deliberate attacker who ALSO forges a consistent footer
        # evades this -- documented ceiling, same as the taint
        # ledger: tamper-evident, not tamper-proof.)
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        led.record(AGENT, DEST + "/2")
        lines = open(p, encoding="utf-8").read().splitlines()
        kept = lines[:-2] + [lines[-1]]
        with open(p, "w", encoding="utf-8") as fh:
            fh.write("\n".join(kept) + "\n")
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)

    def test_byte_tamper_refused(self):
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        raw = open(p, encoding="utf-8").read()
        tampered = raw.replace("vendor", "vend0r")
        self.assertNotEqual(raw, tampered)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(tampered)
        with self.assertRaises(DestinationLedgerError):
            DestinationLedger(p)


class QuerySemanticsTest(unittest.TestCase):
    def test_unknown_destination_not_known(self):
        led = DestinationLedger(_path())
        self.assertFalse(led.known(AGENT, DEST))

    def test_record_refreshes_ttl(self):
        led = DestinationLedger(_path(), ttl_seconds=3600)
        old = datetime.now(timezone.utc) - timedelta(minutes=50)
        led.record(AGENT, DEST, observed_at=old)
        led.record(AGENT, DEST)  # refresh
        self.assertTrue(led.known(AGENT, DEST))

    def test_ttl_expiry(self):
        led = DestinationLedger(_path(), ttl_seconds=3600)
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        led.record(AGENT, DEST, observed_at=old)
        self.assertFalse(led.known(AGENT, DEST))
        self.assertEqual(led.destinations_for(AGENT), [])

    def test_sweep_reaps_expired(self):
        led = DestinationLedger(_path(), ttl_seconds=3600)
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        led.record(AGENT, DEST + "/fresh")
        # Record the expired one LAST: record() sweeps expired
        # entries first, so an earlier expired record would already
        # be gone before the explicit sweep() below.
        led.record(AGENT, DEST, observed_at=old)
        self.assertEqual(led.sweep(), 1)
        self.assertEqual(led.destinations_for(AGENT), [DEST + "/fresh"])

    def test_purge_agent(self):
        led = DestinationLedger(_path())
        led.record(AGENT, DEST)
        led.record(OTHER, DEST)
        self.assertEqual(led.purge(AGENT), 1)
        self.assertFalse(led.known(AGENT, DEST))
        self.assertTrue(led.known(OTHER, DEST))

    def test_purge_all(self):
        led = DestinationLedger(_path())
        led.record(AGENT, DEST)
        led.record(OTHER, DEST + "/2")
        self.assertEqual(led.purge(), 2)
        self.assertEqual(led.destinations_for(OTHER), [])

    def test_identity_isolation(self):
        led = DestinationLedger(_path())
        led.record(AGENT, DEST)
        self.assertFalse(led.known(OTHER, DEST))
        self.assertEqual(led.destinations_for(OTHER), [])

    def test_normalization_strips_whitespace(self):
        led = DestinationLedger(_path())
        led.record(AGENT, "  " + DEST + "  ")
        self.assertTrue(led.known(AGENT, DEST))

    def test_empty_destination_rejected(self):
        led = DestinationLedger(_path())
        with self.assertRaises(DestinationLedgerError):
            led.record(AGENT, "   ")

    def test_non_string_destination_rejected(self):
        led = DestinationLedger(_path())
        with self.assertRaises(DestinationLedgerError):
            led.record(AGENT, {"url": DEST})

    def test_oversize_destination_rejected(self):
        led = DestinationLedger(_path())
        with self.assertRaises(DestinationLedgerError):
            led.record(AGENT, "https://x.local/" + "a" * MAX_DESTINATION_LENGTH)

    def test_query_never_raises(self):
        # A malformed query destination reads as unknown, never as
        # an exception: queries must not break the egress check.
        led = DestinationLedger(_path())
        self.assertFalse(led.known(AGENT, {"url": DEST}))
        self.assertFalse(led.known(AGENT, ""))

    def test_per_agent_cap_evicts_oldest(self):
        led = DestinationLedger(_path(), ttl_seconds=86400)
        base = datetime.now(timezone.utc) - timedelta(hours=2)
        for i in range(MAX_DESTINATIONS_PER_AGENT + 5):
            led.record(AGENT, "https://x.local/%d" % i,
                       observed_at=base + timedelta(seconds=i))
        self.assertEqual(len(led.destinations_for(AGENT)),
                         MAX_DESTINATIONS_PER_AGENT)
        # The 5 oldest evicted; the newest retained.
        self.assertFalse(led.known(AGENT, "https://x.local/0"))
        self.assertTrue(
            led.known(AGENT, "https://x.local/%d"
                      % (MAX_DESTINATIONS_PER_AGENT + 4)))


class TrackerWiringTest(unittest.TestCase):
    DOC = ("Zephyrcorp Industries account ZX-88142 renewal QX-22901 "
           "contact Marlowe Finch.")
    BENIGN = "Weekly status: all systems operational."

    def _egress(self, tracker, agent, dest):
        return tracker.check_egress(agent, "http_post",
                                    {"url": dest, "data": self.BENIGN},
                                    payload_text=self.BENIGN)

    def test_no_ledger_zero_behavior_change(self):
        t1 = rt.RareTokenTracker()
        t1.observe_read(AGENT, "doc-1", self.DOC)
        r1 = self._egress(t1, AGENT, DEST)
        t2 = rt.RareTokenTracker()
        r2 = self._egress(t2, AGENT, DEST)
        self.assertEqual(r1["verdict"], "behavioral_flag")
        # Without a ledger, per-run novelty is unchanged.
        self.assertEqual(r2["verdict"], "allow")  # no read in run 2
        t3 = rt.RareTokenTracker()
        t3.observe_read(AGENT, "doc-1", self.DOC)
        r3 = self._egress(t3, AGENT, DEST)
        self.assertEqual(r3["verdict"], "behavioral_flag")
        self.assertTrue(r3["destination_novel"])

    def test_cross_run_known_destination_silent(self):
        led = DestinationLedger(_path())
        t1 = rt.RareTokenTracker(destination_ledger=led)
        t1.observe_read(AGENT, "doc-1", self.DOC)
        r1 = self._egress(t1, AGENT, DEST)
        self.assertEqual(r1["verdict"], "behavioral_flag")
        t2 = rt.RareTokenTracker(destination_ledger=led)
        t2.observe_read(AGENT, "doc-1", self.DOC)
        r2 = self._egress(t2, AGENT, DEST)
        self.assertEqual(r2["verdict"], "allow")
        self.assertFalse(r2["destination_novel"])

    def test_ledger_file_contains_plaintext_destination(self):
        # Privacy contract: destinations are already audit-logged, so
        # the ledger stores them plaintext like the audit log.
        p = _path()
        led = DestinationLedger(p)
        led.record(AGENT, DEST)
        blob = open(p, encoding="utf-8").read()
        self.assertIn(DEST, blob)

    def test_ledger_failure_propagates_fail_closed(self):
        led = DestinationLedger(_path())
        led.record = lambda *a, **k: (_ for _ in ()).throw(
            DestinationLedgerError("disk full (synthetic)"))
        t = rt.RareTokenTracker(destination_ledger=led)
        with self.assertRaises(DestinationLedgerError):
            self._egress(t, AGENT, DEST)


if __name__ == "__main__":
    unittest.main()
