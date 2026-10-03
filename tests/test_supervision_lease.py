"""Unit tests for the wave-298 supervision<->lease restart composition.

The ``on_restart`` hook the wave-297 lane left documented: lease-gated
children (``requires_lease=True``) are not re-entered after a crash
until ``attest_reacquisition`` proves they hold a fresh lease --
issued after the crash instant, under a different fencing token. The
old token is dead-on-restart; expired obligations escalate signed.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import coordination_lease as lease
from gov import ed25519
from gov import supervision as sup


def _seed(tag):
    return hashlib.sha256(("w298-test-%s" % tag).encode()).digest()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _report(child_seed, child_id, reason, crashed_at):
    body = {"child_id": child_id, "reason_kind": "exit",
            "reason_bytes": reason, "crashed_at": crashed_at}
    raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                     ensure_ascii=True).encode()
    rep = dict(body)
    rep["signature"] = ed25519.sign(child_seed, raw).hex()
    return rep


class ObligationIssuance(unittest.TestCase):
    def _sup(self):
        cs = _seed("child-a")
        ps = _seed("child-b")
        specs = [
            sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100, 3600,
                          requires_lease=True),
            sup.ChildSpec("child-b", _pub(ps), "one_for_one", 100, 3600),
        ]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        return s, {"child-a": cs, "child-b": ps}

    def test_gated_child_gets_obligation(self):
        s, seeds = self._sup()
        d = s.report_crash(
            "child-a", _report(seeds["child-a"], "child-a", "boom", 10),
            at=10, old_fencing_tokens={"child-a": 7})
        obls = d["lease_obligations"]
        self.assertIn("child-a", obls)
        obl = obls["child-a"]
        self.assertEqual(obl["schema"], "supervision/lease-obligation/v1")
        self.assertEqual(obl["old_fencing_token"], 7)
        self.assertEqual(obl["crash_instant"], 10)
        self.assertEqual(obl["expires_at"], 310)  # default 300s TTL
        # Supervisor-signed.
        body = {k: v for k, v in obl.items() if k != "signature"}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
        self.assertIs(ed25519.verify(bytes.fromhex(s.supervisor_pubkey),
                                     raw,
                                     bytes.fromhex(obl["signature"])), True)

    def test_non_gated_child_no_obligation(self):
        s, seeds = self._sup()
        d = s.report_crash(
            "child-b", _report(seeds["child-b"], "child-b", "boom", 10),
            at=10)
        self.assertNotIn("lease_obligations", d)

    def test_non_bool_requires_lease_refuses(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            sup.ChildSpec("c", _pub(_seed("z")), "one_for_one", 5, 60,
                          requires_lease="yes")
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_requires_lease_default_false_and_frozen(self):
        spec = sup.ChildSpec("c", _pub(_seed("z")), "one_for_one", 5, 60)
        self.assertFalse(spec.requires_lease)
        with self.assertRaises(sup.SupervisionError) as cm:
            spec.requires_lease = True
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_obligation_ttl_bounds(self):
        s, seeds = self._sup()
        with self.assertRaises(sup.SupervisionError) as cm:
            s.report_crash(
                "child-a", _report(seeds["child-a"], "child-a", "boom", 10),
                at=10, old_fencing_tokens={"child-a": 7}, obligation_ttl=0)
        self.assertEqual(cm.exception.code, "supervision-invalid")


class Attestation(unittest.TestCase):
    def _world(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        old = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=0)
        d = s.report_crash(
            "child-a", _report(cs, "child-a", "boom", 10), at=10,
            old_fencing_tokens={"child-a": old["fencing_token"]})
        mgr.release("scope-a", old["fencing_token"], "child-a")
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        return s, mgr, auth, old, new, d["lease_obligations"]["child-a"]

    def test_happy_path_reenters(self):
        s, mgr, auth, old, new, obl = self._world()
        self.assertFalse(s.is_reentered("child-a"))
        r = s.attest_reacquisition("child-a", obl, new, _pub(auth), at=30)
        self.assertEqual(r["action"], "reentered")
        self.assertEqual(r["new_fencing_token"], new["fencing_token"])
        self.assertTrue(s.is_reentered("child-a"))

    def test_replay_refuses(self):
        s, mgr, auth, old, new, obl = self._world()
        s.attest_reacquisition("child-a", obl, new, _pub(auth), at=30)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", obl, new, _pub(auth), at=31)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_forged_obligation_refuses(self):
        s, mgr, auth, old, new, obl = self._world()
        forged = dict(obl)
        body = {k: v for k, v in forged.items() if k != "signature"}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
        forged["signature"] = ed25519.sign(_seed("evil-sup"), raw).hex()
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", forged, new, _pub(auth),
                                   at=30)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_same_token_refuses(self):
        s, mgr, auth, old, new, obl = self._world()
        evil = dict(new)
        evil["fencing_token"] = old["fencing_token"]
        body = {k: evil[k] for k in ("scope", "holder_id", "issued_at",
                                    "not_after", "fencing_token",
                                    "authority_pubkey")}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
        evil["signature"] = ed25519.sign(auth, raw).hex()
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", evil, new and evil,
                                   _pub(auth), at=30)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_lease_before_crash_refuses(self):
        s, mgr, auth, old, new, obl = self._world()
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", obl, old, _pub(auth), at=30)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_wrong_holder_refuses(self):
        s, mgr, auth, old, new, obl = self._world()
        other = mgr.acquire("scope-b", 3600, "child-zz",
                            authority_seed=auth, issued_at=20)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", obl, other, _pub(auth), at=30)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_no_old_token_fail_closed(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        auth = _seed("authority")
        mgr = lease.LeaseManager()
        d = s.report_crash(
            "child-a", _report(cs, "child-a", "boom", 10), at=10)
        obl = d["lease_obligations"]["child-a"]
        new = mgr.acquire("scope-a", 3600, "child-a",
                          authority_seed=auth, issued_at=20)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", obl, new, _pub(auth), at=30)
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_plain_child_attest_refuses(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        auth = _seed("authority")
        new = lease.LeaseManager().acquire("scope-a", 3600, "child-a",
                                           authority_seed=auth, issued_at=20)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", {"obligation_id": "x"},
                                   new, _pub(auth), at=30)
        self.assertEqual(cm.exception.code, "supervision-invalid")


class DeadTokenGuard(unittest.TestCase):
    def test_dead_token_refuses_coded(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        s.report_crash("child-a",
                       _report(cs, "child-a", "boom", 10), at=10,
                       old_fencing_tokens={"child-a": 7})
        with self.assertRaises(lease.CoordinationLeaseError) as cm:
            s.guard_write("child-a", 7, at=11)
        self.assertEqual(cm.exception.code, "coord-lease-fencing")

    def test_live_token_passes(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        s.report_crash("child-a",
                       _report(cs, "child-a", "boom", 10), at=10,
                       old_fencing_tokens={"child-a": 7})
        self.assertTrue(s.guard_write("child-a", 8, at=11))
        self.assertTrue(s.guard_write("child-zz", 1, at=11))


class ObligationExpiry(unittest.TestCase):
    def test_expired_obligation_escalates_and_refuses(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        d = s.report_crash(
            "child-a", _report(cs, "child-a", "boom", 10), at=10,
            old_fencing_tokens={"child-a": 7}, obligation_ttl=60)
        obl = d["lease_obligations"]["child-a"]
        n0 = len(s.escalations)
        auth = _seed("authority")
        new = lease.LeaseManager().acquire("scope-a", 3600, "child-a",
                                           authority_seed=auth, issued_at=80)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.attest_reacquisition("child-a", obl, new, _pub(auth), at=100)
        self.assertEqual(cm.exception.code,
                         "supervision-lease-obligation-expired")
        self.assertEqual(len(s.escalations), n0 + 1)
        rec = s.escalations[-1]
        self.assertEqual(rec["code"], "supervision-lease-obligation-expired")
        self.assertTrue(s.verify_escalation(rec))
        self.assertFalse(s.is_reentered("child-a"))

    def test_sweep_escalates_once(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        s.report_crash("child-a", _report(cs, "child-a", "boom", 10),
                       at=10, old_fencing_tokens={"child-a": 7},
                       obligation_ttl=60)
        n0 = len(s.escalations)
        self.assertEqual(s.sweep_obligations(at=100), 1)
        self.assertEqual(len(s.escalations), n0 + 1)
        self.assertEqual(s.sweep_obligations(at=200), 0)
        self.assertEqual(len(s.escalations), n0 + 1)

    def test_sweep_skips_unexpired(self):
        cs = _seed("child-a")
        specs = [sup.ChildSpec("child-a", _pub(cs), "one_for_one", 100,
                               3600, requires_lease=True)]
        s = sup.Supervisor("sup-x", specs, _seed("sup"))
        s.start(at=0)
        s.report_crash("child-a", _report(cs, "child-a", "boom", 10),
                       at=10, old_fencing_tokens={"child-a": 7},
                       obligation_ttl=600)
        self.assertEqual(s.sweep_obligations(at=100), 0)


if __name__ == "__main__":
    unittest.main()
