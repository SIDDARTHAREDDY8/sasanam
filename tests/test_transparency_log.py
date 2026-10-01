"""Unit tests for gov.transparency_log (wave-259 feature lane 1).

Static transparency log for evidence-bundle digests, adapted from the
certificate-transparency pattern (RFC 6962 inclusion/consistency
proofs, signed tree heads) onto the wave-257 static-log architecture.

Tests target the public seam only:
  TransparencyLog.append / inclusion_proof / consistency_proof /
  latest_head / heads / verify_log / detect_equivocation
  verify_tree_head / verify_inclusion / verify_consistency (module level)

Expectations come from the CT semantics in the module docstring, not
from the implementation.
"""

import os
import json
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519 as _ed
from gov import transparency_log as tl


def _tmpdir():
    return tempfile.mkdtemp(prefix="w259tl-", dir="/var/tmp")


def _seed():
    return _ed.generate_seed()


def _pub_hex(seed):
    return bytes(_ed.publickey(seed)).hex()


def _digests(n):
    # Deterministic digest-shaped fixtures (64 lowercase hex chars).
    return ["%064x" % (i + 1) for i in range(n)]


class TestAppend(unittest.TestCase):
    def test_append_returns_signed_tree_head(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        head = log.append(_digests(1)[0])
        self.assertEqual(head["tree_size"], 1)
        self.assertEqual(head["log_id"], _pub_hex(seed))
        self.assertTrue(
            tl.verify_tree_head(head, _pub_hex(seed)),
            "fresh STH must verify under the log key")

    def test_append_without_signing_key_is_refused(self):
        seed = _seed()
        path = _tmpdir()
        tl.TransparencyLog(path, signing_key=seed)  # creates the log
        ro = tl.TransparencyLog(path, public_key=bytes.fromhex(
            _pub_hex(seed)))
        with self.assertRaises(tl.TransparencyLogError):
            ro.append(_digests(1)[0])

    def test_append_malformed_digest_is_refused(self):
        log = tl.TransparencyLog(_tmpdir(), signing_key=_seed())
        for bad in ("", "xyz", "ab" * 31, "AB" * 32, "ab" * 32 + "!",
                    None, 12345):
            with self.assertRaises(tl.TransparencyLogError,
                                   msg="digest %r" % (bad,)):
                log.append(bad)

    def test_append_backdated_timestamp_is_refused(self):
        log = tl.TransparencyLog(_tmpdir(), signing_key=_seed())
        d = _digests(2)
        log.append(d[0], appended_at="2026-10-01T00:00:10Z")
        with self.assertRaises(tl.TransparencyLogError):
            log.append(d[1], appended_at="2026-10-01T00:00:09Z")

    def test_append_equal_timestamp_is_allowed(self):
        # Monotonic non-decreasing: equal timestamps are not backdated.
        log = tl.TransparencyLog(_tmpdir(), signing_key=_seed())
        d = _digests(2)
        log.append(d[0], appended_at="2026-10-01T00:00:10Z")
        head = log.append(d[1], appended_at="2026-10-01T00:00:10Z")
        self.assertEqual(head["tree_size"], 2)

    def test_append_unparseable_timestamp_is_refused(self):
        log = tl.TransparencyLog(_tmpdir(), signing_key=_seed())
        with self.assertRaises(tl.TransparencyLogError):
            log.append(_digests(1)[0], appended_at="not-a-time")


class TestInclusion(unittest.TestCase):
    def _log(self, n):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        digests = _digests(n)
        for d in digests:
            log.append(d)
        return log, seed, digests

    def test_inclusion_round_trip_every_leaf(self):
        for n in (1, 2, 3, 5, 8, 13):
            log, seed, digests = self._log(n)
            head = log.latest_head()
            pub = _pub_hex(seed)
            for d in digests:
                proof = log.inclusion_proof(d)
                self.assertTrue(
                    tl.verify_inclusion(d, proof, head, pub),
                    "leaf %s... at n=%d must verify"
                    % (d[:8], n))

    def test_inclusion_proof_bound_to_tree_size(self):
        # A proof built at tree size n does not verify against the
        # head at tree size n+1 (different root, different size).
        log, seed, digests = self._log(4)
        proof = log.inclusion_proof(digests[0], tree_size=2)
        self.assertEqual(proof["tree_size"], 2)
        head4 = log.latest_head()
        self.assertEqual(head4["tree_size"], 4)
        self.assertFalse(tl.verify_inclusion(
            digests[0], proof, head4, _pub_hex(seed)))

    def test_inclusion_proof_for_older_head(self):
        # The same proof DOES verify against the head at its own size.
        log, seed, digests = self._log(4)
        proof = log.inclusion_proof(digests[1], tree_size=3)
        heads = log.heads()
        head3 = [h for h in heads if h["tree_size"] == 3][0]
        self.assertTrue(tl.verify_inclusion(
            digests[1], proof, head3, _pub_hex(seed)))

    def test_inclusion_unknown_digest_has_no_proof(self):
        log, _seed2, _digests2 = self._log(3)
        with self.assertRaises(tl.TransparencyLogError):
            log.inclusion_proof("ff" * 32)

    def test_duplicate_digest_returns_first_index(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        d = _digests(1)[0]
        log.append(d)
        log.append(d)  # duplicates are legal (CT semantics)
        proof = log.inclusion_proof(d)
        self.assertEqual(proof["leaf_index"], 0)
        self.assertTrue(tl.verify_inclusion(
            d, proof, log.latest_head(), _pub_hex(seed)))

    def test_verify_inclusion_without_pubkey_trusts_head_as_given(self):
        # The 3-arg form from the task: caller verified the STH
        # signature separately.
        log, seed, digests = self._log(3)
        head = log.latest_head()
        pub = _pub_hex(seed)
        self.assertTrue(tl.verify_tree_head(head, pub))
        proof = log.inclusion_proof(digests[2])
        self.assertTrue(tl.verify_inclusion(digests[2], proof, head))


class TestConsistency(unittest.TestCase):
    def test_consistency_round_trip(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        pub = _pub_hex(seed)
        for d in _digests(9):
            log.append(d)
        heads = log.heads()
        for m in (1, 2, 5, 8):
            proof = log.consistency_proof(m, 9)
            old = [h for h in heads if h["tree_size"] == m][0]
            new = [h for h in heads if h["tree_size"] == 9][0]
            self.assertTrue(
                tl.verify_consistency(old, new, proof, pub),
                "consistency %d -> 9 must verify" % m)

    def test_consistency_proof_binds_head_sizes(self):
        # A proof for (2,5) presented with the head at size 7 is
        # meaningless and must be refused.
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        pub = _pub_hex(seed)
        for d in _digests(7):
            log.append(d)
        heads = log.heads()
        proof = log.consistency_proof(2, 5)
        old2 = [h for h in heads if h["tree_size"] == 2][0]
        new7 = [h for h in heads if h["tree_size"] == 7][0]
        self.assertFalse(tl.verify_consistency(old2, new7, proof, pub))

    def test_consistency_out_of_range_is_refused(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        for d in _digests(3):
            log.append(d)
        with self.assertRaises(tl.TransparencyLogError):
            log.consistency_proof(4, 3)
        with self.assertRaises(tl.TransparencyLogError):
            log.consistency_proof(2, 99)


class TestAudit(unittest.TestCase):
    def test_verify_log_ok(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        for d in _digests(5):
            log.append(d)
        ok, detail = log.verify_log()
        self.assertTrue(ok, detail)

    def test_verify_log_catches_rewritten_leaf(self):
        # Rewrite a leaf's digest in leaves.jsonl: the heads no longer
        # match the recomputed roots.
        seed = _seed()
        path = _tmpdir()
        log = tl.TransparencyLog(path, signing_key=seed)
        for d in _digests(4):
            log.append(d)
        leaves_path = os.path.join(path, "leaves.jsonl")
        with open(leaves_path, encoding="utf-8") as f:
            lines = f.read().splitlines()
        rec = json.loads(lines[1])
        rec["digest"] = "ff" * 32
        lines[1] = json.dumps(rec, sort_keys=True,
                              separators=(",", ":"))
        with open(leaves_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        log2 = tl.TransparencyLog(path, signing_key=seed)
        ok, detail = log2.verify_log()
        self.assertFalse(ok)
        self.assertIn("rewritten", detail)

    def test_detect_equivocation(self):
        # Two validly-signed heads at the same tree size with
        # different roots: the split-view. A malicious operator CAN
        # produce this (same key, divergent histories); the module
        # detects it, it does not prevent it.
        seed = _seed()
        log_a = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        log_b = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        da = _digests(3)
        db = ["%064x" % (100 + i) for i in range(3)]
        for x, y in zip(da, db):
            log_a.append(x)
            log_b.append(y)
        heads_a = log_a.heads()
        heads_b = log_b.heads()
        self.assertTrue(tl.verify_tree_head(heads_a[1], _pub_hex(seed)))
        self.assertTrue(tl.verify_tree_head(heads_b[1], _pub_hex(seed)))
        self.assertNotEqual(heads_a[1]["root_hash"],
                            heads_b[1]["root_hash"])
        self.assertEqual(log_a.detect_equivocation(heads_a), [])
        conflicts = log_a.detect_equivocation(heads_a + [heads_b[1]])
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["tree_size"], 2)
        self.assertEqual(len(conflicts[0]["root_hashes"]), 2)

    def test_key_confusion_refused(self):
        seed = _seed()
        path = _tmpdir()
        tl.TransparencyLog(path, signing_key=seed)
        other = _seed()
        with self.assertRaises(tl.TransparencyLogError):
            tl.TransparencyLog(path, signing_key=other)


class TestWitnessedState(unittest.TestCase):
    """F230: verify_log(expected_size/expected_head) detects the log
    shrinking below previously witnessed state."""

    def _truncated(self, n=5, keep=4):
        seed = _seed()
        path = _tmpdir()
        log = tl.TransparencyLog(path, signing_key=seed)
        for d in _digests(n):
            log.append(d)
        witness = log.latest_head()
        for fname in (tl.LEAVES_FILE, tl.HEADS_FILE):
            fpath = os.path.join(path, fname)
            with open(fpath, encoding="utf-8") as f:
                lines = f.read().splitlines()
            with open(fpath, "w", encoding="utf-8") as f:
                f.write("\n".join(lines[:keep]) + "\n")
        reopened = tl.TransparencyLog(
            path, public_key=bytes.fromhex(_pub_hex(seed)))
        return reopened, witness

    def test_truncation_detected_vs_witnessed_head(self):
        reopened, witness = self._truncated()
        ok, detail = reopened.verify_log(expected_head=witness)
        self.assertFalse(ok)
        self.assertIn("shrank", detail)

    def test_truncation_detected_vs_witnessed_size(self):
        reopened, _witness = self._truncated()
        ok, detail = reopened.verify_log(expected_size=5)
        self.assertFalse(ok)
        self.assertIn("shrank", detail)

    def test_no_false_alarm_without_truncation(self):
        seed = _seed()
        path = _tmpdir()
        log = tl.TransparencyLog(path, signing_key=seed)
        for d in _digests(5):
            log.append(d)
        witness = log.latest_head()
        ok, detail = log.verify_log(expected_head=witness)
        self.assertTrue(ok, detail)
        ok, detail = log.verify_log(expected_size=5)
        self.assertTrue(ok, detail)

    def test_older_witnessed_head_no_false_alarm(self):
        seed = _seed()
        path = _tmpdir()
        log = tl.TransparencyLog(path, signing_key=seed)
        for d in _digests(5):
            log.append(d)
        witness2 = [h for h in log.heads()
                    if h["tree_size"] == 2][0]
        ok, detail = log.verify_log(expected_head=witness2)
        self.assertTrue(ok, detail)

    def test_forged_witnessed_head_refused_not_raised(self):
        reopened, witness = self._truncated()
        forged = dict(witness)
        forged["root_hash"] = "ff" * 32
        forged["signature"] = "00" * 128
        self.assertFalse(
            tl.verify_tree_head(forged, reopened._log_id))
        ok, detail = reopened.verify_log(expected_head=forged)
        self.assertFalse(ok)
        self.assertIn("does not verify", detail)

    def test_expected_size_misuse_raises(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        log.append(_digests(1)[0])
        for bad in (-1, True, "5", 2.0):
            with self.assertRaises(tl.TransparencyLogError,
                                   msg="expected_size %r" % (bad,)):
                log.verify_log(expected_size=bad)

    def test_expected_size_head_disagreement_raises(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        for d in _digests(3):
            log.append(d)
        witness = log.latest_head()
        with self.assertRaises(tl.TransparencyLogError):
            log.verify_log(expected_size=2, expected_head=witness)


class TestEquivocationVerification(unittest.TestCase):
    """F231: only signature-valid heads feed equivocation detection."""

    def test_unsigned_head_ignored_by_default(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        head = log.append(_digests(1)[0])
        forged = dict(head)
        forged["root_hash"] = "ff" * 32
        forged["signature"] = "00" * 128
        self.assertFalse(tl.verify_tree_head(forged, _pub_hex(seed)))
        self.assertEqual(log.detect_equivocation([head, forged]), [])

    def test_strict_reports_invalid_input(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        head = log.append(_digests(1)[0])
        forged = dict(head)
        forged["root_hash"] = "ff" * 32
        forged["signature"] = "00" * 128
        with self.assertRaises(tl.TransparencyLogError):
            log.detect_equivocation([head, forged], strict=True)

    def test_strict_ok_on_valid_heads(self):
        seed = _seed()
        log = tl.TransparencyLog(_tmpdir(), signing_key=seed)
        for d in _digests(2):
            log.append(d)
        self.assertEqual(
            log.detect_equivocation(log.heads(), strict=True), [])


class TestOperatorIoErrors(unittest.TestCase):
    """F232: operator-path I/O failures arrive as
    TransparencyLogError, never raw OSError."""

    def test_init_on_path_that_is_a_file(self):
        fd, fpath = tempfile.mkstemp(prefix="w261tl-file-", dir="/var/tmp")
        os.close(fd)
        try:
            with self.assertRaises(tl.TransparencyLogError):
                tl.TransparencyLog(fpath, signing_key=_seed())
        finally:
            os.unlink(fpath)

    def test_append_when_leaves_is_a_directory(self):
        seed = _seed()
        path = _tmpdir()
        log = tl.TransparencyLog(path, signing_key=seed)
        log.append(_digests(1)[0])
        os.remove(os.path.join(path, tl.LEAVES_FILE))
        os.mkdir(os.path.join(path, tl.LEAVES_FILE))
        with self.assertRaises(tl.TransparencyLogError):
            log.append(_digests(2)[1])

    def test_reopen_when_leaves_not_a_regular_file(self):
        seed = _seed()
        path = _tmpdir()
        tl.TransparencyLog(path, signing_key=seed)
        os.mkdir(os.path.join(path, tl.LEAVES_FILE))
        with self.assertRaises(tl.TransparencyLogError):
            tl.TransparencyLog(
                path, public_key=bytes.fromhex(_pub_hex(seed)))


if __name__ == "__main__":
    unittest.main()
