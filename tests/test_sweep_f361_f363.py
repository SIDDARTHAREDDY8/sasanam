"""Regression tests for F361-F363 (wave-293 lane 6 uncoded-exception sweep).

F361: revocation_status verify_credential / verify_status_response refuse
      coded revocation-status-unverifiable on non-canonicalizable inputs
      (circular structures -> ValueError, mixed-type keys -> TypeError).
F362: issuance_monitor verify_monitor_report refuses coded
      issuance-monitor-misissuance on a circular report.
F363: delegation_chain digest_of refuses coded delegation-malformed on a
      circular body (F359 fixed TypeError only; F363 adds ValueError).
"""

import unittest

from gov import delegation_chain as dc
from gov import ed25519
from gov import issuance_monitor as im
from gov import revocation_status as rs


def _registry():
    seed = ed25519.generate_seed()
    reg = rs.RevocationRegistry("reg-test-1", seed)
    return reg, reg.registry_pubkey_hex()


class TestF361RevocationVerifySeams(unittest.TestCase):
    def test_circular_credential_refuses_coded(self):
        reg, pub = _registry()
        reg.issue("c1", "ab" * 32, 1700000000, 1700003600)
        bad = {"credential_format": rs.CREDENTIAL_FORMAT, "rid": "c1",
               "holder_pubkey": "ab" * 32}
        bad["evil"] = bad
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.verify_credential({"credential": bad, "signature": "cd" * 64,
                                  "keyid": "registry"}, pub)
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_mixed_key_credential_refuses_coded(self):
        reg, pub = _registry()
        reg.issue("c1", "ab" * 32, 1700000000, 1700003600)
        bad = {"credential_format": rs.CREDENTIAL_FORMAT, "rid": "c1",
               "holder_pubkey": "ab" * 32, 1: "x", "a": "y"}
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.verify_credential({"credential": bad, "signature": "cd" * 64,
                                  "keyid": "registry"}, pub)
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_circular_status_refuses_coded(self):
        reg, pub = _registry()
        reg.issue("c1", "ab" * 32, 1700000000, 1700003600)
        bad = {"response_format": rs.STATUS_FORMAT, "rid": "c1",
               "state": "active", "checked_at": 1, "successor": None,
               "revoked_at": None, "revoke_reason": None,
               "registry_digest": "ef" * 32}
        bad["evil"] = bad
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.verify_status_response({"status": bad, "signature": "cd" * 64,
                                       "keyid": "registry"}, pub)
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_well_formed_credential_still_verifies(self):
        reg, pub = _registry()
        env = reg.issue("c1", "ab" * 32, 1700000000, 1700003600)
        self.assertEqual(rs.verify_credential(env, pub)["rid"], "c1")


class TestF362MonitorReportSeam(unittest.TestCase):
    def test_circular_report_refuses_coded(self):
        mseed = ed25519.generate_seed()
        mpub = ed25519.publickey(mseed).hex()
        bad = {"report_format": im.REPORT_FORMAT, "policy_id": "p",
               "policy_digest": "ef" * 32, "scanned_at": 1,
               "entry_count": 0, "findings": []}
        bad["evil"] = bad
        with self.assertRaises(im.MonitorError) as ctx:
            im.verify_monitor_report({"report": bad, "signature": "cd" * 64,
                                      "keyid": "monitor"}, mpub)
        self.assertEqual(ctx.exception.code, "issuance-monitor-misissuance")

    def test_well_formed_report_still_verifies(self):
        mseed = ed25519.generate_seed()
        mpub = ed25519.publickey(mseed).hex()
        policy = im.MonitorPolicy("p1", {"k1": "ab" * 32}, (1, 2))
        report = im.scan_issuance_log([], policy, mseed, scanned_at=1)
        self.assertEqual(im.verify_monitor_report(report, mpub)
                         ["entry_count"], 0)


class TestF363DigestOfSeam(unittest.TestCase):
    def test_circular_body_refuses_coded(self):
        bad = {}
        bad["self"] = bad
        with self.assertRaises(dc.DelegationMalformed):
            dc.digest_of(bad)

    def test_plain_body_still_digests(self):
        self.assertEqual(dc.digest_of({"a": 1}), dc.digest_of({"a": 1}))


if __name__ == "__main__":
    unittest.main()
