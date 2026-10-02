"""Unit tests for gov/permit_journal.py (W250-3 event-sourced permit
journal lane).

Lane-local taxonomy pin: 988 (979 + 9 permit-journal codes), additive
only; merge coordinator recomposes.
"""

import json
import os
import shutil
import sys
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import decision_codes
from gov import permit_journal as pj


def _key():
    return os.urandom(32)


class _Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w250-pj-test-")
        self.key = _key()
        self.path = os.path.join(self.tmp, "j.jsonl")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def journal(self, key=None):
        return pj.PermitJournal(self.path,
                                key=self.key if key is None else key)


class TaxonomyPinTest(_Base):
    def test_taxonomy_pin_988(self):
        # Wave-250 lane 3: 979 + 9 permit-journal codes, additive only;
        # merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1684)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.

    def test_new_codes_registered(self):
        for code in ("permit-journal-chain-broken",
                     "permit-journal-corrupted",
                     "permit-journal-duplicate-event",
                     "permit-journal-key-weak",
                     "permit-journal-misuse",
                     "permit-journal-snapshot-tampered",
                     "permit-journal-transition-illegal",
                     "permit-journal-unknown-permit",
                     "permit-journal-write-conflict"):
            self.assertIn(code, decision_codes.TAXONOMY)


class LifecycleTest(_Base):
    def test_grant_use_finalize(self):
        j = self.journal()
        j.grant("p", {"scope": "read"})
        j.record_use("p", {"tool": "shell"})
        j.finalize("p", "r" * 64)
        st = j.permit_state("p")
        self.assertEqual(st["state"], "finalized")
        self.assertEqual(st["terminal"], pj.PERMIT_FINALIZED)
        self.assertEqual(st["n_events"], 3)
        self.assertEqual(st["granted"]["payload"]["scope"], "read")

    def test_unknown_permit_query(self):
        j = self.journal()
        st = j.permit_state("nope")
        self.assertEqual(st["state"], "unknown")
        self.assertEqual(st["n_events"], 0)

    def test_expire_and_revoke_payloads(self):
        j = self.journal()
        j.grant("a", {})
        j.expire("a", "ttl elapsed")
        j.grant("b", {})
        j.revoke("b", "recall", revoked_by="op-9")
        self.assertEqual(j.permit_state("a")["state"], "expired")
        rev = j.permit_state("b")
        self.assertEqual(rev["state"], "revoked")
        self.assertEqual(rev["terminal_event"]["payload"]["revoked_by"],
                         "op-9")

    def test_permit_ids_sorted(self):
        j = self.journal()
        j.grant("zeta", {})
        j.grant("alpha", {})
        self.assertEqual(j.permit_ids(), ["alpha", "zeta"])


class RefusalTest(_Base):
    def _code(self, fn):
        with self.assertRaises(pj.PermitJournalError) as ctx:
            fn()
        return ctx.exception.code

    def test_second_grant_refused(self):
        j = self.journal()
        j.grant("p", {})
        self.assertEqual(self._code(lambda: j.grant("p", {})),
                         "permit-journal-transition-illegal")

    def test_use_on_terminal_refused(self):
        j = self.journal()
        j.grant("p", {})
        j.revoke("p", "r")
        for fn in (lambda: j.record_use("p", {}),
                   lambda: j.expire("p", "x"),
                   lambda: j.finalize("p", "y")):
            self.assertEqual(self._code(fn),
                             "permit-journal-transition-illegal")

    def test_unknown_permit_refused(self):
        j = self.journal()
        self.assertEqual(
            self._code(lambda: j.expire("ghost", "x")),
            "permit-journal-unknown-permit")

    def test_duplicate_event_id_refused(self):
        j = self.journal()
        j.grant("p", {}, event_id="dup-id")
        self.assertEqual(
            self._code(lambda: j.grant("q", {}, event_id="dup-id")),
            "permit-journal-duplicate-event")

    def test_short_key_refused(self):
        self.assertEqual(
            self._code(lambda: pj.PermitJournal(
                os.path.join(self.tmp, "k.jsonl"), key=b"tiny")),
            "permit-journal-key-weak")

    def test_bad_env_key_refused(self):
        os.environ["GOV_PERMIT_JOURNAL_KEY"] = "not-hex!!"
        try:
            code = self._code(lambda: pj.PermitJournal(
                os.path.join(self.tmp, "e.jsonl")))
        finally:
            del os.environ["GOV_PERMIT_JOURNAL_KEY"]
        self.assertEqual(code, "permit-journal-key-weak")

    def test_misuse_bad_payload(self):
        j = self.journal()
        self.assertEqual(
            self._code(lambda: j.grant("p", "not-a-dict")),
            "permit-journal-misuse")

    def test_misuse_empty_permit_id(self):
        j = self.journal()
        self.assertEqual(
            self._code(lambda: j.grant("", {})),
            "permit-journal-misuse")


class DurabilityTest(_Base):
    def test_restart_replays(self):
        j = self.journal()
        j.grant("p", {"scope": "read"})
        j.record_use("p", {"tool": "x"})
        del j
        j2 = self.journal()
        st = j2.permit_state("p")
        self.assertEqual(st["state"], "used")
        self.assertEqual(st["n_events"], 2)

    def test_env_key_roundtrip(self):
        os.environ["GOV_PERMIT_JOURNAL_KEY"] = self.key.hex()
        try:
            j = pj.PermitJournal(self.path)  # no kwarg: env wins
            j.grant("p", {})
            del j
            j2 = pj.PermitJournal(self.path)
            self.assertEqual(j2.permit_state("p")["state"], "granted")
        finally:
            del os.environ["GOV_PERMIT_JOURNAL_KEY"]

    def test_wrong_key_fails_closed(self):
        j = self.journal()
        j.grant("p", {})
        del j
        code = None
        try:
            self.journal(key=os.urandom(32))
        except pj.PermitJournalError as exc:
            code = exc.code
        self.assertEqual(code, "permit-journal-chain-broken")


class CompactionTest(_Base):
    def test_snapshot_compact_roundtrip(self):
        j = self.journal()
        j.grant("p1", {"scope": "read"})
        j.record_use("p1", {"tool": "x"})
        j.grant("p2", {})
        ref = j.take_snapshot()
        self.assertIn("snapshot_path", ref)
        j.compact()
        del j
        j2 = self.journal()
        self.assertEqual(j2.permit_state("p1")["state"], "used")
        self.assertEqual(j2.permit_state("p2")["state"], "granted")
        # chain continues after the snapshot boundary
        j2.finalize("p1", "r" * 64)
        self.assertEqual(j2.permit_state("p1")["state"], "finalized")

    def test_compact_without_snapshot_refused(self):
        j = self.journal()
        j.grant("p", {})
        with self.assertRaises(ValueError):
            j.compact()


if __name__ == "__main__":
    unittest.main()
