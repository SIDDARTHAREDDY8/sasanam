"""Unit tests: octet-digest receipt chaining (wave-234).

Public seams only (except one documented defense-in-depth branch):
* gov.log.ActionLog.append stamps prev_record_octets_digest;
  genesis uses OCTET_DIGEST_GENESIS; the field is reserved chain
  metadata (caller-supplied values are dropped); the digest equals
  SHA-256 of the previous record's exact stored line bytes.
* gov.log.verify_chain(path, require_octet_digest=True) verifies
  every link against the actual stored octets; refusals name the
  chain-domain taxonomy codes.
* Default verify_chain(path) behavior is unchanged (tighten-only).
* The field is HMAC-bound: tampering breaks the MAC.
"""

import hashlib
import json
import os
import sys
import tempfile
import unittest

_TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
for _p in (_TESTS_DIR, os.path.dirname(_TESTS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from keyfixture import provision_test_key  # noqa: E402
from gov.log import (  # noqa: E402
    FORMAT_VERSION,
    OCTET_DIGEST_GENESIS,
    ActionLog,
    OctetDigestError,
    _active_key,
    _canonical,
    _checkpoint_mac,
    _compute_mac,
    verify_chain,
)


def _reanchor_tail_checkpoint(log_dir, seq, new_hash):
    """Rewrite the seq-N checkpoint line with new_hash + a fresh MAC
    (a fully consistent forgery re-anchors the sidecar too)."""
    key, epoch = _active_key()
    cp_path = os.path.join(log_dir, "checkpoints.jsonl")
    out = []
    with open(cp_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            cp = json.loads(line)
            if cp.get("seq") == seq:
                cp = {"seq": seq, "hash": new_hash,
                      "key_epoch": epoch,
                      "format_version": FORMAT_VERSION,
                      "mac": _checkpoint_mac(key, epoch, seq, new_hash)}
                line = json.dumps(cp, ensure_ascii=True)
            out.append(line)
    with open(cp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")


def _write_legacy_log(path, raws):
    """Legacy-style log: no digest fields, MACs and checkpoint sidecar
    recomputed so the chain is otherwise fully valid."""
    key, epoch = _active_key()
    lines, cps = [], []
    prev = "GENESIS"
    for raw in raws:
        e = json.loads(raw.decode("utf-8"))
        e.pop("prev_record_octets_digest", None)
        # Re-chain: prev_hash must point at the recomputed predecessor
        # hash, not the original (which covered the removed field).
        e["prev_hash"] = prev
        e["hash"] = _compute_mac(key, epoch, e["prev_hash"],
                                 _canonical(e))
        prev = e["hash"]
        lines.append((json.dumps(e, ensure_ascii=True) + "\n")
                     .encode("utf-8"))
        cps.append({"seq": e["seq"], "hash": e["hash"],
                    "key_epoch": epoch, "format_version": FORMAT_VERSION,
                    "mac": _checkpoint_mac(key, epoch, e["seq"],
                                           e["hash"])})
    with open(path, "wb") as f:
        f.write(b"".join(lines))
    with open(os.path.join(os.path.dirname(path), "checkpoints.jsonl"),
              "w", encoding="utf-8") as f:
        for cp in cps:
            f.write(json.dumps(cp, ensure_ascii=True) + "\n")


class OctetChainTest(unittest.TestCase):
    def setUp(self):
        provision_test_key(epoch="octet-chain-tests")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)

    def _path(self, name="audit.jsonl"):
        return os.path.join(self._tmp.name, name)

    def _write(self, n=4, strict=False, name="audit.jsonl"):
        log = ActionLog(self._path(name),
                        require_octet_digest=strict)
        for i in range(n):
            log.append({"kind": "octet-test", "i": i})
        return log

    def _raw_lines(self, path):
        with open(path, "rb") as f:
            return [l for l in f.read().split(b"\n") if l.strip()]

    def test_writer_stamps_digest_over_previous_octets(self):
        path = self._path()
        self._write(3, name="audit.jsonl")
        raws = self._raw_lines(path)
        entries = [json.loads(r.decode("utf-8")) for r in raws]
        # Genesis: the documented constant, no previous record.
        self.assertEqual(entries[0]["prev_record_octets_digest"],
                         OCTET_DIGEST_GENESIS)
        self.assertEqual(OCTET_DIGEST_GENESIS, "0" * 64)
        # Every later link commits to the previous record's EXACT
        # stored bytes (line terminator included).
        for i in (1, 2):
            self.assertEqual(
                entries[i]["prev_record_octets_digest"],
                hashlib.sha256(raws[i - 1] + b"\n").hexdigest())

    def test_require_verify_accepts_clean_chain(self):
        path = self._path()
        self._write(4)
        ok, broken, n = verify_chain(path, require_octet_digest=True)
        self.assertTrue(ok, "clean chain failed require verify")
        self.assertIsNone(broken)
        self.assertEqual(n, 4)

    def test_default_verify_unchanged(self):
        path = self._path()
        self._write(3)
        self.assertEqual(verify_chain(path), (True, None, 3))
        # ... and a legacy log (no digest fields at all) still
        # verifies clean under the default. It lives in its own
        # directory so its checkpoint sidecar anchors it.
        os.mkdir(os.path.join(self._tmp.name, "legacy"))
        legacy = os.path.join(self._tmp.name, "legacy", "audit.jsonl")
        raws = self._raw_lines(path)
        _write_legacy_log(legacy, raws)
        self.assertEqual(verify_chain(legacy), (True, None, 3))

    def test_reencoded_previous_refused(self):
        # Deliberate failure mode: re-encode the previous record
        # (byte-different, semantically equal), re-link the next entry
        # over the re-encoded bytes with a VALID MAC. The octet check
        # must refuse even though MAC and prev_hash are intact.
        path = self._path()
        self._write(3)
        raws = self._raw_lines(path)
        e2 = json.loads(raws[1].decode("utf-8"))
        reencoded = (json.dumps(e2, sort_keys=True, ensure_ascii=True)
                     + "\n").encode("utf-8")
        self.assertNotEqual(reencoded, raws[1] + b"\n")
        e3 = json.loads(raws[2].decode("utf-8"))
        e3["prev_record_octets_digest"] = hashlib.sha256(
            reencoded).hexdigest()
        key, epoch = _active_key()
        e3["hash"] = _compute_mac(key, epoch, e3["prev_hash"],
                                  _canonical(e3))
        forged = (json.dumps(e3, ensure_ascii=True) + "\n").encode("utf-8")
        with open(path, "wb") as f:
            f.write(raws[0] + b"\n" + raws[1] + b"\n" + forged)
        # Fully consistent forgery: re-anchor the checkpoint sidecar
        # to the re-linked tail, so MACs, prev_hash links, AND
        # checkpoints all verify. Only the octet layer sees it.
        _reanchor_tail_checkpoint(self._tmp.name, 3, e3["hash"])
        ok, broken, n = verify_chain(path, require_octet_digest=True)
        self.assertFalse(ok, "re-encoded previous record was accepted")
        # The default (opt-out) check still accepts: only the octet
        # layer is stricter.
        self.assertEqual(verify_chain(path), (True, None, 3))

    def test_absent_field_refused_not_degraded(self):
        legacy_dir = os.path.join(self._tmp.name, "legacy")
        os.mkdir(legacy_dir)
        path = os.path.join(legacy_dir, "audit.jsonl")
        self._write(3)
        raws = self._raw_lines(self._path())
        _write_legacy_log(path, raws)
        ok, broken, n = verify_chain(path, require_octet_digest=True)
        self.assertFalse(ok, "legacy log without digest fields verified "
                             "under require_octet_digest=True")

    def test_truncated_previous_refused_not_skipped(self):
        path = self._path()
        self._write(3)
        raws = self._raw_lines(path)
        truncated = raws[1][:len(raws[1]) // 2]
        self.assertNotEqual(truncated, raws[1])
        with open(path, "wb") as f:
            f.write(raws[0] + b"\n" + truncated + b"\n" + raws[2] + b"\n")
        ok, broken, n = verify_chain(path, require_octet_digest=True)
        self.assertFalse(ok, "truncated previous record was accepted")

    def test_caller_cannot_forge_field(self):
        path = self._path()
        log = ActionLog(path)
        log.append({"kind": "a"})
        bogus = "f" * 64
        stored = log.append({"kind": "b",
                             "prev_record_octets_digest": bogus})
        raws = self._raw_lines(path)
        expected = hashlib.sha256(raws[0] + b"\n").hexdigest()
        self.assertEqual(stored["prev_record_octets_digest"], expected)
        self.assertNotEqual(stored["prev_record_octets_digest"], bogus)
        ok, broken, n = verify_chain(path, require_octet_digest=True)
        self.assertEqual((ok, n), (True, 2))

    def test_field_is_hmac_bound(self):
        # Flipping one hex char of the digest field must break the MAC.
        path = self._path()
        self._write(3)
        raws = self._raw_lines(path)
        e2 = json.loads(raws[1].decode("utf-8"))
        old = e2["prev_record_octets_digest"]
        e2["prev_record_octets_digest"] = (
            ("0" if old[0] != "0" else "1") + old[1:])
        forged = (json.dumps(e2, ensure_ascii=True) + "\n").encode("utf-8")
        with open(path, "wb") as f:
            f.write(raws[0] + b"\n" + forged + b"\n" + raws[2] + b"\n")
        ok, broken, n = verify_chain(path)
        self.assertFalse(ok, "tampered digest field passed default verify")

    def test_strict_writer_defensive_refusal(self):
        # Defense-in-depth: refresh() always captures the tail bytes,
        # so this branch is unreachable via the public API; the test
        # pins the fail-closed invariant directly.
        path = self._path()
        log = ActionLog(path, require_octet_digest=True)
        log.append({"kind": "a"})
        log._prev_raw = None  # simulate unavailable tail octets
        with self.assertRaises(OctetDigestError) as ctx:
            log.append({"kind": "b"})
        self.assertEqual(ctx.exception.code, "chain-octet-digest-absent")

    def test_octet_digest_error_carries_code(self):
        err = OctetDigestError("chain-octet-digest-mismatch", "seq 3")
        self.assertEqual(err.code, "chain-octet-digest-mismatch")
        self.assertIn("chain-octet-digest-mismatch", str(err))
        self.assertIn("seq 3", str(err))


if __name__ == "__main__":
    unittest.main()
