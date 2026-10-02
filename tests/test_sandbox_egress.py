#!/usr/bin/env python3
"""Unit tests for gov/sandbox_egress.py (wave-278 lane 3).

Covers: SandboxNetworkPolicy parsing/validation (fail-closed),
deny-by-default semantics, SandboxEgressController runtime mutation,
SandboxEgressAuditor hash chaining, and the screen_egress_url L7 seam.
"""

import hashlib
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO not in sys.path:
    sys.path.insert(0, REPO)

from gov import sandbox_egress as se  # noqa: E402
from gov.egress_proxy import PolicyRefusedError  # noqa: E402


def _policy(**kw):
    data = {"version": "v1", "allow_out": ["victim.example:80"]}
    data.update(kw)
    return se.SandboxNetworkPolicy(data)


class PolicyParseTests(unittest.TestCase):
    def test_valid(self):
        p = _policy()
        self.assertEqual(p.version, "v1")
        self.assertTrue(p.allows("victim.example", 80))
        self.assertEqual(len(p.policy_hash), 64)

    def test_unknown_keys_refused(self):
        with self.assertRaises(PolicyRefusedError):
            _policy(deny_out=["0.0.0.0/0"])

    def test_empty_version_refused(self):
        with self.assertRaises(PolicyRefusedError):
            _policy(version="  ")

    def test_allow_out_must_be_list(self):
        with self.assertRaises(PolicyRefusedError):
            _policy(allow_out="victim.example:80")

    def test_allow_out_entry_shapes_refused(self):
        for bad in ("noport", "h:0", "h:99999", "h:notaport",
                    "bad host!:80", "[::1]:80", 42, ("h", 80)):
            with self.assertRaises(PolicyRefusedError, msg=repr(bad)):
                _policy(allow_out=[bad])

    def test_host_lowercased(self):
        p = _policy(allow_out=["VICTIM.EXAMPLE:80"])
        self.assertTrue(p.allows("victim.example", 80))

    def test_digests_must_be_hex64(self):
        with self.assertRaises(PolicyRefusedError):
            _policy(sensitive_digests=["xyz"])
        p = _policy(sensitive_digests=["AB" * 32])
        self.assertIn("ab" * 32, p.sensitive_digests)

    def test_budget_must_be_positive_int(self):
        with self.assertRaises(PolicyRefusedError):
            _policy(max_ref_payload_chars=0)
        with self.assertRaises(PolicyRefusedError):
            _policy(max_ref_payload_chars=True)

    def test_non_dict_refused(self):
        with self.assertRaises(PolicyRefusedError):
            se.SandboxNetworkPolicy("v1")


class DenyByDefaultTests(unittest.TestCase):
    def test_unlisted_denied(self):
        p = _policy()
        self.assertFalse(p.allows("evil.example", 443))
        self.assertFalse(p.allows("victim.example", 443))  # wrong port
        self.assertFalse(p.allows("sub.victim.example", 80))  # no suffix

    def test_empty_allow_out_denies_all(self):
        p = _policy(allow_out=[])
        self.assertFalse(p.allows("victim.example", 80))

    def test_allows_never_raises(self):
        p = _policy()
        self.assertFalse(p.allows(None, "x"))
        self.assertFalse(p.allows("victim.example", None))


class ControllerTests(unittest.TestCase):
    def test_update_swaps_live(self):
        c = se.SandboxEgressController(_policy())
        self.assertTrue(c.current.allows("victim.example", 80))
        c.update({"version": "v2", "allow_out": []})
        self.assertEqual(c.current.version, "v2")
        self.assertFalse(c.current.allows("victim.example", 80))

    def test_malformed_update_keeps_old(self):
        c = se.SandboxEgressController(_policy())
        with self.assertRaises(PolicyRefusedError):
            c.update({"version": "", "allow_out": []})
        self.assertEqual(c.current.version, "v1")
        self.assertTrue(c.current.allows("victim.example", 80))

    def test_update_events_chained(self):
        aud = se.SandboxEgressAuditor()
        c = se.SandboxEgressController(_policy(), auditor=aud)
        c.update({"version": "v2", "allow_out": []})
        kinds = [e["kind"] for e in aud.events]
        self.assertEqual(kinds, ["policy-attached", "policy-updated"])
        upd = aud.events[1]
        self.assertEqual(upd["detail"]["version"], "v2")
        self.assertNotEqual(upd["detail"]["prev_hash"],
                            upd["detail"]["new_hash"])
        self.assertTrue(aud.verify())

    def test_rejects_non_policy(self):
        with self.assertRaises(PolicyRefusedError):
            se.SandboxEgressController(object())


class AuditorTests(unittest.TestCase):
    def test_chain_verifies(self):
        aud = se.SandboxEgressAuditor()
        aud.event("a", {"x": 1})
        aud.event("b", {"y": 2})
        self.assertTrue(aud.verify())
        self.assertEqual([e["seq"] for e in aud.events], [0, 1])
        self.assertEqual(aud.events[1]["prev_hash"],
                         aud.events[0]["entry_hash"])

    def test_tamper_detected(self):
        aud = se.SandboxEgressAuditor()
        aud.event("a", {"x": 1})
        aud._events[0]["detail"]["x"] = 999
        self.assertFalse(aud.verify())

    def test_never_raises_on_unserializable(self):
        aud = se.SandboxEgressAuditor()
        entry = aud.event("a", {"x": object()})
        self.assertIn("entry_hash", entry)
        self.assertTrue(aud.verify())

    def test_on_event_mirror_best_effort(self):
        seen = []

        def bad_mirror(entry):
            seen.append(entry["kind"])
            raise RuntimeError("mirror down")

        aud = se.SandboxEgressAuditor(on_event=bad_mirror)
        entry = aud.event("a", {})
        self.assertEqual(seen, ["a"])  # mirror attempted...
        self.assertTrue(aud.verify())  # ...but the chain stands


class ScreenUrlTests(unittest.TestCase):
    def test_quad_encoded_refused(self):
        from gov import egress_refs as er
        secret = "zx/qw/er_ty-99"
        enc = secret
        import urllib.parse as up
        for _ in range(4):
            enc = up.quote(enc, safe="")
        pol = er.EgressPolicy(
            sensitive_digests=(hashlib.sha256(
                secret.encode()).hexdigest(),))
        verdict, code, _ = er.screen_egress_url(
            "http://victim.example/x?d=" + enc, policy=pol)
        self.assertEqual(verdict, "refuse")
        self.assertEqual(code, "egress-ref-data-exfil")

    def test_benign_allowed(self):
        from gov import egress_refs as er
        verdict, code, _ = er.screen_egress_url(
            "http://victim.example/search?q=hello%20world")
        self.assertEqual(verdict, "allow")
        self.assertIsNone(code)

    def test_never_raises(self):
        from gov import egress_refs as er
        for bad in (None, "", ":///", "\x00" * 100):
            verdict, _, _ = er.screen_egress_url(bad)
            self.assertIn(verdict, ("allow", "refuse"))

    def test_to_egress_refs_policy_carries_digests(self):
        d = hashlib.sha256(b"x").hexdigest()
        p = _policy(sensitive_digests=[d], max_ref_payload_chars=100)
        rp = p.to_egress_refs_policy()
        self.assertIn(d, rp.sensitive_digests)
        self.assertEqual(rp.max_ref_payload_chars, 100)


if __name__ == "__main__":
    unittest.main()
