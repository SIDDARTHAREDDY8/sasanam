"""Unit tests for gov.witness_daemon (wave-339 lane 2, R24).

Covers the C2SP add-checkpoint daemon state machine, the log-side
block-until-quorum submission client, and the HTTP harness wiring.
Deterministic (fixed seeds); stdlib only; no network (transports are
in-process doubles).
"""

import base64
import hashlib
import os
import tempfile
import threading
import unittest

from gov import witness_daemon as WD
from gov import witness_policy as WP
from gov import witness_consistency as WC
from gov import checkpoint_note as CN
from gov.witness_log import WitnessLog
from gov.signing import Ed25519Signer

_SEED_LOG = bytes(range(32))
_SEED_W1 = bytes([255 - i for i in range(32)])
_SEED_W2 = bytes([(i * 7) % 256 for i in range(32)])
_SEED_W3 = bytes([(i * 13 + 5) % 256 for i in range(32)])
_SEED_P1 = bytes([(i * 3 + 11) % 256 for i in range(32)])
_SEED_P2 = bytes([(i * 5 + 17) % 256 for i in range(32)])

_NOW = 1798765432
_ORIGIN = "sasanam-witness-test/v1"
_LOG_KEY_NAME = "oplog"


def _signer(seed):
    return Ed25519Signer(seed)


def _log_vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519, signer.public_key),
        CN.SIG_TYPE_ED25519, signer.public_key)


def _wit_vkey(name, signer):
    return CN.vkey_string(
        name, CN.derive_key_id(name, CN.SIG_TYPE_ED25519_COSIGNATURE_V1,
                               signer.public_key),
        CN.SIG_TYPE_ED25519_COSIGNATURE_V1, signer.public_key)


def _make_log(n):
    log = WitnessLog(_signer(_SEED_LOG).public_key)
    for i in range(n):
        log.append(b"leaf-%d" % i)
    return log


def _note(log):
    return CN.emit_checkpoint(_ORIGIN, len(log), log.root_hash(),
                              _LOG_KEY_NAME, _SEED_LOG)


class _T(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="w339-ut-")
        known = {_ORIGIN: [_log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))]}
        self.daemon = WD.WitnessDaemon(
            known, "wit1", _signer(_SEED_W1),
            os.path.join(self.tmp, "w.db"))

    def body(self, log, old, note):
        lines = ["old %d" % old]
        if 0 < old < len(log):
            for h in log.consistency_proof(old, len(log))["hashes"]:
                lines.append(base64.b64encode(
                    bytes.fromhex(h)).decode("ascii"))
        lines.append("")
        return "\n".join(lines) + "\n" + note.decode("utf-8")

    def entries(self):
        return [
            {"name": "wit1", "vkey": _wit_vkey("wit1", _signer(_SEED_W1)),
             "endpoint": "u1"},
            {"name": "wit2", "vkey": _wit_vkey("wit2", _signer(_SEED_W2)),
             "endpoint": "u2"},
        ]

    def policy(self):
        body = {
            "schema": "witness-policy/v1",
            "policy_id": "sasanam-witness-policy",
            "version": 1,
            "issued_at": _NOW - 1000,
            "expires_at": _NOW + 86400 * 90,
            "threshold": 2,
            "log": {"name": _LOG_KEY_NAME,
                    "vkey": _log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))},
            "witnesses": [
                {"name": "wit1",
                 "vkey": _wit_vkey("wit1", _signer(_SEED_W1)),
                 "operator": "op1", "contact": "w1@example.org",
                 "not_before": _NOW - 100000, "not_after": _NOW + 100000,
                 "status": "usable"},
                {"name": "wit2",
                 "vkey": _wit_vkey("wit2", _signer(_SEED_W2)),
                 "operator": "op2", "contact": "w2@example.org",
                 "not_before": _NOW - 100000, "not_after": _NOW + 100000,
                 "status": "usable"},
            ],
            "policy_signers": [
                {"key_id": _signer(_SEED_P1).public_key.hex(),
                 "public_key": _signer(_SEED_P1).public_key.hex()}],
            "policy_threshold": 1,
            "max_checkpoint_staleness_seconds": 10800,
        }
        return WP.verify_policy_document(
            WP.seal_policy(body, [_signer(_SEED_P1)]),
            {"policy_signers": body["policy_signers"],
             "policy_threshold": 1}, _NOW)


class TestDaemonWire(_T):
    def test_bootstrap_and_advance(self):
        log = _make_log(2)
        st, resp = self.daemon.handle_add_checkpoint(
            self.body(log, 0, _note(log)), _NOW)
        self.assertEqual(st, 200)
        self.assertTrue(resp.strip().startswith(str(CN.EM_DASH)))
        log.append(b"leaf-2")
        st, _ = self.daemon.handle_add_checkpoint(
            self.body(log, 2, _note(log)), _NOW)
        self.assertEqual(st, 200)

    def test_cosignature_verifies_against_witness_vkey(self):
        log = _make_log(2)
        st, resp = self.daemon.handle_add_checkpoint(
            self.body(log, 0, _note(log)), _NOW)
        self.assertEqual(st, 200)
        combined = _note(log) + resp.encode("utf-8")
        fields = CN.verify_checkpoint(
            combined, [_wit_vkey("wit1", _signer(_SEED_W1))])
        self.assertIn("wit1", fields["verified_by"])
        # The cosignature statement is domain-separated: it does NOT
        # sign the note text.
        text, sigs = CN._split_note(combined)
        wit = [s for s in sigs if s["key_name"] == "wit1"][0]
        stmt = CN.cosignature_v1_statement(
            _ORIGIN, 2, log.root_hash(),
            int.from_bytes(wit["signature"][:8], "big"))
        from gov.ed25519 import verify as _ed_verify
        self.assertIs(
            _ed_verify(_signer(_SEED_W1).public_key, stmt,
                       wit["signature"][8:]), True)

    def test_unknown_origin_404(self):
        note = CN.emit_checkpoint("nope/v1", 1, bytes(32),
                                  _LOG_KEY_NAME, _SEED_LOG)
        st, _ = self.daemon.handle_add_checkpoint(
            "old 0\n\n" + note.decode(), _NOW)
        self.assertEqual(st, 404)

    def test_monitor_surface(self):
        log = _make_log(2)
        self.daemon.handle_add_checkpoint(
            self.body(log, 0, _note(log)), _NOW)
        oh = hashlib.sha256(_ORIGIN.encode()).hexdigest()
        note = self.daemon.monitor_note(oh)
        self.assertIsNotNone(note)
        self.assertIn(b"wit1", note)
        self.assertIsNone(self.daemon.monitor_note("0" * 64))
        self.assertIsNone(self.daemon.monitor_note("bogus"))

    def test_concurrent_submits_serialize(self):
        log = _make_log(4)
        self.daemon.handle_add_checkpoint(
            self.body(log, 0, _note(log)), _NOW)
        results = []

        def worker():
            st, _ = self.daemon.handle_add_checkpoint(
                self.body(log, 4, _note(log)), _NOW)
            results.append(st)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), [200] * 8)
        self.assertEqual(self.daemon._stored(_ORIGIN)[0], 4)

    def test_state_failure_is_coded(self):
        # A daemon whose store is unusable refuses coded instead of
        # cosigning without persist.
        daemon = WD.WitnessDaemon(
            {_ORIGIN: [_log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))]},
            "wit1", _signer(_SEED_W1), ":memory:")
        daemon._conn.close()
        log = _make_log(2)
        with self.assertRaises(WD.WitnessDaemonError) as ctx:
            daemon.handle_add_checkpoint(
                self.body(log, 0, _note(log)), _NOW)
        self.assertEqual(ctx.exception.code, "witness-daemon-state-failed")


class TestSubmitClient(_T):
    def _daemons(self):
        out = []
        for name, seed in (("wit1", _SEED_W1), ("wit2", _SEED_W2)):
            d = tempfile.mkdtemp(prefix="w339-utcli-")
            known = {_ORIGIN: [_log_vkey(_LOG_KEY_NAME,
                                        _signer(_SEED_LOG))]}
            out.append((WD.WitnessDaemon(
                known, name, _signer(seed),
                os.path.join(d, "w.db")), name))
        return out

    def test_quorum_happy_path(self):
        daemons = self._daemons()
        by_name = dict((n, d) for d, n in daemons)

        def transport(entry, body, timeout):
            return by_name[entry["name"]].handle_add_checkpoint(body, _NOW)

        log = _make_log(3)
        state = {}
        out = WD.submit_checkpoint(
            log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME,
            log_seed=_SEED_LOG, witnesses=self.entries(), quorum_k=2,
            policy=self.policy(), transport=transport, state=state,
            now=_NOW)
        self.assertEqual(out["cosigned_by"], ["wit1", "wit2"])
        self.assertEqual(state, {"wit1": 3, "wit2": 3})
        vi = WP.verifier_inputs(self.policy(), _NOW)
        WC.require_cosignatures(
            out["checkpoint"], operator_vkeys=vi["operator_vkeys"],
            witness_vkeys={n: vi["witness_vkeys"][n]
                           for n in ("wit1", "wit2")}, quorum_k=2)

    def test_below_quorum_freezes(self):
        def down(entry, body, timeout):
            raise ConnectionError("outage")

        log = _make_log(3)
        state = {"wit1": 1}
        with self.assertRaises(WD.WitnessSubmitError) as ctx:
            WD.submit_checkpoint(
                log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME,
                log_seed=_SEED_LOG, witnesses=self.entries(), quorum_k=2,
                policy=self.policy(), transport=down, state=state,
                now=_NOW)
        self.assertEqual(ctx.exception.code, "witness-publish-quorum-unmet")
        self.assertEqual(state, {"wit1": 1})  # untouched: the freeze

    def test_quorum_disagreement_with_policy_refuses(self):
        daemons = self._daemons()
        by_name = dict((n, d) for d, n in daemons)

        def transport(entry, body, timeout):
            return by_name[entry["name"]].handle_add_checkpoint(body, _NOW)

        log = _make_log(3)
        with self.assertRaises(WD.WitnessSubmitError) as ctx:
            WD.submit_checkpoint(
                log, origin=_ORIGIN, log_key_name=_LOG_KEY_NAME,
                log_seed=_SEED_LOG, witnesses=self.entries(), quorum_k=9,
                policy=self.policy(), transport=transport, state={},
                now=_NOW)
        self.assertEqual(ctx.exception.code, "witness-note-malformed")


class TestDualThreshold(unittest.TestCase):
    def _body(self, version, signers, pth):
        return {
            "schema": "witness-policy/v1",
            "policy_id": "sasanam-witness-policy",
            "version": version,
            "issued_at": _NOW - 1000,
            "expires_at": _NOW + 86400 * 90,
            "threshold": 1,
            "log": {"name": _LOG_KEY_NAME,
                    "vkey": _log_vkey(_LOG_KEY_NAME, _signer(_SEED_LOG))},
            "witnesses": [{
                "name": "wit1",
                "vkey": _wit_vkey("wit1", _signer(_SEED_W1)),
                "operator": "op1", "contact": "w1@example.org",
                "not_before": _NOW - 100000, "not_after": _NOW + 100000,
                "status": "usable"}],
            "policy_signers": [
                {"key_id": s.public_key.hex(),
                 "public_key": s.public_key.hex()} for s in signers],
            "policy_threshold": pth,
            "max_checkpoint_staleness_seconds": 10800,
        }

    def test_rotation_needs_both_thresholds(self):
        old_body = self._body(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
        anchor = {"policy_signers": old_body["policy_signers"],
                  "policy_threshold": 2}
        old = WP.verify_policy_document(
            WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
            anchor, _NOW)
        new_body = self._body(2, [_signer(_SEED_P2),
                                  _signer(_SEED_W3)], 2)
        # Old-set-only authority: refused.
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.check_policy_update(
                old, WP.seal_policy(new_body, [_signer(_SEED_P1),
                                              _signer(_SEED_P2)]),
                anchor, _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-dual-threshold-unmet")
        # Both sides: accepted.
        got = WP.check_policy_update(
            old, WP.seal_policy(new_body, [_signer(_SEED_P1),
                                          _signer(_SEED_P2),
                                          _signer(_SEED_W3)]),
            anchor, _NOW)
        self.assertEqual(got["version"], 2)

    def test_unchanged_set_skips_dual(self):
        old_body = self._body(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
        anchor = {"policy_signers": old_body["policy_signers"],
                  "policy_threshold": 2}
        old = WP.verify_policy_document(
            WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
            anchor, _NOW)
        new_body = self._body(2, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
        got = WP.check_policy_update(
            old, WP.seal_policy(new_body, [_signer(_SEED_P1),
                                          _signer(_SEED_P2)]),
            anchor, _NOW)
        self.assertEqual(got["version"], 2)

    def test_known_bad_signature_is_forgery_signal(self):
        old_body = self._body(1, [_signer(_SEED_P1), _signer(_SEED_P2)], 2)
        anchor = {"policy_signers": old_body["policy_signers"],
                  "policy_threshold": 2}
        old = WP.verify_policy_document(
            WP.seal_policy(old_body, [_signer(_SEED_P1), _signer(_SEED_P2)]),
            anchor, _NOW)
        new_body = self._body(2, [_signer(_SEED_P1), _signer(_SEED_W3)], 2)
        doc = WP.seal_policy(new_body, [_signer(_SEED_P1), _signer(_SEED_P2),
                                        _signer(_SEED_W3)])
        # Corrupt P1's signature bytes: known signer, bad signature.
        raw = bytearray(bytes.fromhex(doc["signatures"][0]["sig"]))
        raw[-1] ^= 1
        doc["signatures"][0]["sig"] = bytes(raw).hex()
        with self.assertRaises(WP.WitnessPolicyError) as ctx:
            WP.check_policy_update(old, doc, anchor, _NOW)
        self.assertEqual(ctx.exception.code,
                         "witness-policy-signature-invalid")


class TestHttpHarness(_T):
    def test_handler_serves_add_checkpoint(self):
        import http.client
        import urllib.request as urlreq

        daemon = self.daemon
        handler = WD.make_http_handler(daemon)
        from http.server import HTTPServer
        httpd = HTTPServer(("127.0.0.1", 0), handler)
        port = httpd.server_address[1]
        t = threading.Thread(target=httpd.serve_forever, daemon=True)
        t.start()
        try:
            log = _make_log(2)
            body = self.body(log, 0, _note(log)).encode("utf-8")
            req = urlreq.Request(
                "http://127.0.0.1:%d/add-checkpoint" % port, data=body,
                method="POST")
            with urlreq.urlopen(req, timeout=10) as resp:
                self.assertEqual(resp.status, 200)
                payload = resp.read().decode()
            self.assertIn("wit1", payload)
            # Monitor surface.
            oh = hashlib.sha256(_ORIGIN.encode()).hexdigest()
            with urlreq.urlopen(
                    "http://127.0.0.1:%d/%s/checkpoint" % (port, oh),
                    timeout=10) as resp:
                self.assertEqual(resp.status, 200)
        finally:
            httpd.shutdown()
            t.join(timeout=10)

    def test_make_handler_rejects_non_daemon(self):
        with self.assertRaises(ValueError):
            WD.make_http_handler(object())


if __name__ == "__main__":
    unittest.main()
