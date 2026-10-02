"""Unit tests for gov/revocation_status.py and gov/issuance_monitor.py.

Wave-292 lane 2: pin 1730 -> 1730 (+4 revocation-*/issuance-*).
"""

import unittest

from gov import ed25519
from gov import evidence_provenance as ep
from gov import issuance_monitor as im
from gov import revocation_status as rs


def _seed():
    return ed25519.generate_seed()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _registry():
    reg = rs.RevocationRegistry("reg-unit", _seed())
    hpub = _pub(_seed())
    return reg, hpub


def _mpol(issuer_keys=None, window=(1000, 2000)):
    mseed = _seed()
    if issuer_keys is None:
        issuer_keys = {"issuer-a": _pub(_seed())}
    return im.MonitorPolicy("mp-unit", issuer_keys, window), mseed


def _entry(rid, keyid, holder, issued_at):
    return {"rid": rid, "issuer_keyid": keyid,
            "holder_pubkey": holder, "issued_at": issued_at}


class RevocationRegistryTests(unittest.TestCase):
    def test_issue_and_verify(self):
        reg, hpub = _registry()
        cred = reg.issue("cred-001", hpub, 1000, 2000, ["read"])
        got = rs.verify_credential(cred, reg.registry_pubkey_hex())
        self.assertEqual(got["rid"], "cred-001")
        self.assertEqual(got["capabilities"], ["read"])

    def test_issue_forged_signature_refuses(self):
        reg, hpub = _registry()
        cred = reg.issue("cred-001", hpub, 1000, 2000)
        evil = rs.RevocationRegistry("evil", _seed())
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.verify_credential(cred, evil.registry_pubkey_hex())
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_duplicate_rid_refuses(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        with self.assertRaises(rs.RevocationError) as ctx:
            reg.issue("cred-001", hpub, 1000, 2000)
        self.assertEqual(ctx.exception.code,
                         "revocation-entry-unverifiable")

    def test_rotate_retires_old_with_successor(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        newcred, _ = reg.rotate("cred-001", "cred-002", hpub, 1600, 2600)
        rs.verify_credential(newcred, reg.registry_pubkey_hex())
        st = rs.verify_status_response(reg.check_status("cred-001", 1700),
                                       reg.registry_pubkey_hex())
        self.assertEqual(st["state"], "retired")
        self.assertEqual(st["successor"], "cred-002")

    def test_retired_reuse_is_revocation_event(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        reg.rotate("cred-001", "cred-002", hpub, 1600, 2600)
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.enforce_revocation(reg.check_status("cred-001", 1700),
                                  reg.registry_pubkey_hex())
        # Not an auth failure: a coded revocation event.
        self.assertEqual(ctx.exception.code, "revocation-retired-reuse")

    def test_rotate_inactive_refuses(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        reg.rotate("cred-001", "cred-002", hpub, 1600, 2600)
        with self.assertRaises(rs.RevocationError) as ctx:
            reg.rotate("cred-001", "cred-003", hpub, 1700, 2700)
        self.assertEqual(ctx.exception.code, "revocation-refused")

    def test_revoke_refuses(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        self.assertTrue(reg.revoke("cred-001", "compromise"))
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.enforce_revocation(reg.check_status("cred-001", 1500),
                                  reg.registry_pubkey_hex())
        self.assertEqual(ctx.exception.code, "revocation-revoked")

    def test_revoke_idempotent(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        reg.revoke("cred-001", "compromise")
        self.assertTrue(reg.revoke("cred-001", "compromise"))

    def test_unknown_rid_fail_closed(self):
        reg, _ = _registry()
        with self.assertRaises(rs.RevocationError) as ctx:
            reg.check_status("nope", 1500)
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_status_envelope_tamper(self):
        reg, hpub = _registry()
        reg.issue("cred-001", hpub, 1000, 2000)
        st = reg.check_status("cred-001", 1500)
        tampered = {"status": dict(st["status"], state="revoked"),
                    "signature": st["signature"], "keyid": st["keyid"]}
        with self.assertRaises(rs.RevocationError) as ctx:
            rs.verify_status_response(tampered, reg.registry_pubkey_hex())
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_gate_require_all(self):
        reg, hpub = _registry()
        reg.issue("a", hpub, 1000, 2000)
        reg.issue("b", hpub, 1000, 2000)
        gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["a", "b"])
        self.assertTrue(gate.require_all([reg.check_status("a", 1500),
                                          reg.check_status("b", 1500)]))
        with self.assertRaises(rs.RevocationError) as ctx:
            gate.require_all([reg.check_status("a", 1500)])
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")

    def test_gate_vacuous_refused(self):
        reg, _ = _registry()
        with self.assertRaises(rs.RevocationError):
            rs.RevocationGate(reg.registry_pubkey_hex(), [])

    def test_grammar_rid(self):
        reg, hpub = _registry()
        with self.assertRaises(rs.RevocationError):
            reg.issue("bad rid!", hpub, 1000, 2000)

    def test_sink_isolation(self):
        # F345-class: a raising audit sink cannot break issuance.
        reg, hpub = _registry()
        old = rs._EMIT
        rs._EMIT = lambda event, fields: (_ for _ in ()).throw(
            RuntimeError("sink down"))
        try:
            cred = reg.issue("cred-001", hpub, 1000, 2000)
            self.assertTrue(rs.enforce_revocation(
                reg.check_status("cred-001", 1500),
                reg.registry_pubkey_hex()))
        finally:
            rs._EMIT = old
        self.assertEqual(cred["credential"]["rid"], "cred-001")


class IssuanceMonitorTests(unittest.TestCase):
    def test_clean_log(self):
        pol, mseed = _mpol()
        holder = _pub(_seed())
        rep = im.scan_issuance_log([_entry("r1", "issuer-a", holder, 1500)],
                                   pol, mseed, 1600)
        vrep = im.verify_monitor_report(
            rep, ed25519.publickey(mseed).hex())
        self.assertEqual(vrep["findings"], [])
        self.assertTrue(im.refuse_on_misissuance(vrep))

    def test_unexpected_issuer(self):
        pol, mseed = _mpol()
        rep = im.scan_issuance_log(
            [_entry("r1", "rogue", _pub(_seed()), 1500)], pol, mseed, 1600)
        vrep = im.verify_monitor_report(
            rep, ed25519.publickey(mseed).hex())
        self.assertEqual([f["kind"] for f in vrep["findings"]],
                         ["unexpected-issuer-key"])
        with self.assertRaises(im.MonitorError) as ctx:
            im.refuse_on_misissuance(vrep)
        self.assertEqual(ctx.exception.code, "issuance-monitor-misissuance")

    def test_rid_collision(self):
        pol, mseed = _mpol()
        rep = im.scan_issuance_log(
            [_entry("r1", "issuer-a", _pub(_seed()), 1500),
             _entry("r1", "issuer-a", _pub(_seed()), 1501)],
            pol, mseed, 1600)
        vrep = im.verify_monitor_report(
            rep, ed25519.publickey(mseed).hex())
        self.assertEqual([f["kind"] for f in vrep["findings"]],
                         ["rid-collision"])

    def test_cross_issuer_duplicate(self):
        mseed = _seed()
        keys = {"issuer-a": _pub(_seed()), "issuer-b": _pub(_seed())}
        pol = im.MonitorPolicy("mp-x", keys, (1000, 2000))
        holder = _pub(_seed())
        rep = im.scan_issuance_log(
            [_entry("r1", "issuer-a", holder, 1500),
             _entry("r1", "issuer-b", holder, 1501)], pol, mseed, 1600)
        vrep = im.verify_monitor_report(
            rep, ed25519.publickey(mseed).hex())
        self.assertEqual([f["kind"] for f in vrep["findings"]],
                         ["duplicate-rid-different-issuer"])

    def test_window_boundaries_inclusive(self):
        pol, mseed = _mpol()
        holder = _pub(_seed())
        rep = im.scan_issuance_log(
            [_entry("e1", "issuer-a", holder, 1000),
             _entry("e2", "issuer-a", holder, 2000)], pol, mseed, 2000)
        vrep = im.verify_monitor_report(
            rep, ed25519.publickey(mseed).hex())
        self.assertEqual(vrep["findings"], [])
        rep2 = im.scan_issuance_log(
            [_entry("b1", "issuer-a", holder, 999),
             _entry("b2", "issuer-a", holder, 2001)], pol, mseed, 2001)
        vrep2 = im.verify_monitor_report(
            rep2, ed25519.publickey(mseed).hex())
        self.assertEqual({f["kind"] for f in vrep2["findings"]},
                         {"outside-issuance-window"})

    def test_report_tamper(self):
        pol, mseed = _mpol()
        rep = im.scan_issuance_log(
            [_entry("r1", "rogue", _pub(_seed()), 1500)], pol, mseed, 1600)
        stripped = {"report": dict(rep["report"], findings=[]),
                    "signature": rep["signature"], "keyid": rep["keyid"]}
        with self.assertRaises(im.MonitorError) as ctx:
            im.verify_monitor_report(stripped,
                                     ed25519.publickey(mseed).hex())
        self.assertEqual(ctx.exception.code, "issuance-monitor-misissuance")

    def test_vacuous_policy_refused(self):
        with self.assertRaises(im.MonitorError):
            im.MonitorPolicy("mp-empty", {}, (1000, 2000))

    def test_policy_digest_stable(self):
        pol, _ = _mpol()
        self.assertEqual(pol.policy_digest(), pol.policy_digest())


class ProvenanceOptInTests(unittest.TestCase):
    def _env_policy(self, revocation_required=()):
        bseed = _seed()
        bpub = _pub(bseed)
        policy = ep.BuilderPolicy("auditor-opt", {"builder-1": bpub},
                                  revocation_required=revocation_required)
        claim = ep.make_provenance_claim(
            "builder-1", "key-1", "ab" * 32,
            [{"uri": "src/a", "digest": "cd" * 32,
              "completeness": "verified"}],
            issued_at=1700000000)
        return ep.seal_provenance(claim, bseed), policy

    def test_default_posture_unchanged(self):
        env, policy = self._env_policy()
        self.assertTrue(ep.verify_provenance(env, policy))

    def test_optin_active_passes(self):
        reg = rs.RevocationRegistry("reg-opt", _seed())
        hpub = _pub(_seed())
        reg.issue("cred-001", hpub, 1000, 2000)
        gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
        env, policy = self._env_policy(revocation_required=["cred-001"])
        self.assertTrue(ep.verify_provenance(
            env, policy, revocation_gate=gate,
            revocation_statuses=[reg.check_status("cred-001", 1500)]))

    def test_optin_retired_refuses_coded(self):
        reg = rs.RevocationRegistry("reg-opt", _seed())
        hpub = _pub(_seed())
        reg.issue("cred-001", hpub, 1000, 2000)
        reg.rotate("cred-001", "cred-002", hpub, 1600, 2600)
        gate = rs.RevocationGate(reg.registry_pubkey_hex(), ["cred-001"])
        env, policy = self._env_policy(revocation_required=["cred-001"])
        with self.assertRaises(rs.RevocationError) as ctx:
            ep.verify_provenance(
                env, policy, revocation_gate=gate,
                revocation_statuses=[reg.check_status("cred-001", 1700)])
        self.assertEqual(ctx.exception.code, "revocation-retired-reuse")

    def test_demand_without_gate_fails_closed(self):
        env, policy = self._env_policy(revocation_required=["cred-001"])
        with self.assertRaises(ep.ProvenanceError) as ctx:
            ep.verify_provenance(env, policy)
        self.assertEqual(ctx.exception.code,
                         "revocation-status-unverifiable")


if __name__ == "__main__":
    unittest.main()
