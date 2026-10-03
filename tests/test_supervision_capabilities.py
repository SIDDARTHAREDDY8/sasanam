"""Unit tests for the wave-299 lane-4 Fuchsia-style capability manifests
in gov/supervision.py.

Declared use/offer/expose with rights-attenuation checked at offer
time (failing closed before the child ever runs); the endowment
distinguishes holding from routing (no silent retention); expose
routes further only with a matching from:<child> endowment entry;
restart decisions carry each manifested child's exact grant.
"""

import hashlib
import json
import os
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import ed25519
from gov import supervision as sup


def _seed(tag):
    return hashlib.sha256(("w299-test-cm-%s" % tag).encode()).digest()


def _pub(seed):
    return ed25519.publickey(seed).hex()


def _manifest(use=(), offer=(), expose=()):
    return {"use": list(use), "offer": list(offer), "expose": list(expose)}


def _use(cap, rights, src="parent"):
    return {"capability": cap, "rights": list(rights), "from": src}


def _spec(cid, seed_tag, manifest=None, **kw):
    return sup.ChildSpec(cid, _pub(_seed(seed_tag)), "one_for_one",
                         100, 3600, capabilities=manifest, **kw)


def _sup(name, specs, endowment):
    s = sup.Supervisor(name, specs, _seed("sup-%s" % name),
                       endowment=endowment)
    s.start(at=0)
    return s


class ManifestDeclaration(unittest.TestCase):
    def test_valid_manifest_accepted(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("fs-read", ["r"], "parent")]))
        self.assertEqual(spec.manifest["use"][0]["capability"], "fs-read")

    def test_no_manifest_is_none(self):
        spec = _spec("child-a", "c-a")
        self.assertIsNone(spec.capabilities)
        self.assertIsNone(spec.manifest)

    def test_missing_section_refused(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            _spec("child-a", "c-a", {"use": []})
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_empty_rights_refused(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            _spec("child-a", "c-a",
                  _manifest(use=[_use("fs-read", [], "parent")]))
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_bad_right_token_refused(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            _spec("child-a", "c-a",
                  _manifest(use=[_use("fs-read", ["RW"], "parent")]))
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_custom_right_token_accepted(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("queue", ["enqueue", "dequeue"], "self")]))
        self.assertEqual(spec.manifest["use"][0]["rights"],
                         ["dequeue", "enqueue"])

    def test_duplicate_capability_in_section_refused(self):
        with self.assertRaises(sup.SupervisionError) as cm:
            _spec("child-a", "c-a", _manifest(
                use=[_use("fs-read", ["r"], "parent"),
                     _use("fs-read", ["w"], "self")]))
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_frozen_at_declaration(self):
        spec = _spec("child-a", "c-a",
                     _manifest(use=[_use("fs-read", ["r"], "parent")]))
        with self.assertRaises(sup.SupervisionError) as cm:
            spec.capabilities = None
        self.assertEqual(cm.exception.code, "supervision-invalid")

    def test_deep_freeze(self):
        spec = _spec("child-a", "c-a",
                     _manifest(use=[_use("fs-read", ["r"], "parent")]))
        s = _sup("sup-df", [spec], {"fs-read": {"r"}})
        leaked = spec.manifest
        leaked["use"].append(_use("net", ["r", "w"], "parent"))
        leaked["use"][0]["rights"].append("w")
        self.assertEqual(s.granted_capabilities("child-a"),
                         {"fs-read": ["r"]})


class OfferTimeAttenuation(unittest.TestCase):
    def test_use_wider_than_held_refused(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("fs-read", ["r", "w"], "parent")]))
        with self.assertRaises(sup.SupervisionError) as cm:
            _sup("sup-att", [spec], {"fs-read": {"r"}})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-rights-exceeded")

    def test_use_of_unheld_capability_refused(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("net", ["r"], "parent")]))
        with self.assertRaises(sup.SupervisionError) as cm:
            _sup("sup-und", [spec], {"fs-read": {"r"}})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-undeclared")

    def test_use_from_self_needs_no_endowment(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("mem", ["r", "w"], "self")]))
        s = _sup("sup-self", [spec], None)
        self.assertEqual(s.granted_capabilities("child-a"),
                         {"mem": ["r", "w"]})

    def test_offer_without_hold_refused(self):
        spec = _spec("child-a", "c-a", _manifest(
            offer=[_use("fs-read", ["r"], "parent")]))
        with self.assertRaises(sup.SupervisionError) as cm:
            _sup("sup-noh", [spec], {"fs-read": {"r"}})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-undeclared")

    def test_offer_wider_than_held_refused(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("fs-read", ["r"], "parent")],
            offer=[_use("fs-read", ["r", "w"], "parent")]))
        with self.assertRaises(sup.SupervisionError) as cm:
            _sup("sup-ow", [spec], {"fs-read": {"r", "w"}})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-rights-exceeded")

    def test_offer_within_hold_accepted(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("fs-read", ["r", "w"], "parent")],
            offer=[_use("fs-read", ["r"], "parent")]))
        _sup("sup-ok", [spec], {"fs-read": {"r", "w"}})  # no raise

    def test_endowment_named_child_undeclared(self):
        spec = _spec("child-a", "c-a")
        with self.assertRaises(sup.SupervisionError) as cm:
            _sup("sup-nc", [spec],
                 {"pipe": {"rights": {"r"}, "held": "route",
                           "from": "ghost-child"}})
        self.assertEqual(cm.exception.code, "supervision-undeclared-child")


class NoSilentRetention(unittest.TestCase):
    def test_exercise_held_for_use_ok(self):
        s = _sup("sup-use", [_spec("child-a", "c-a")],
                 {"fs-read": {"rights": {"r", "w"}, "held": "use",
                              "from": "parent"}})
        self.assertTrue(s.exercise("fs-read", {"r"}))

    def test_exercise_merely_routed_refused(self):
        s = _sup("sup-nsr", [_spec("child-a", "c-a")],
                 {"metrics": {"rights": {"r"}, "held": "route",
                              "from": "parent"}})
        with self.assertRaises(sup.SupervisionError) as cm:
            s.exercise("metrics", {"r"})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-route-violation")

    def test_exercise_undeclared_refused(self):
        s = _sup("sup-eu", [_spec("child-a", "c-a")],
                 {"fs-read": {"r"}})
        with self.assertRaises(sup.SupervisionError) as cm:
            s.exercise("net", {"r"})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-undeclared")

    def test_exercise_wider_than_held_refused(self):
        s = _sup("sup-ew", [_spec("child-a", "c-a")],
                 {"fs-read": {"rights": {"r"}, "held": "use",
                              "from": "parent"}})
        with self.assertRaises(sup.SupervisionError) as cm:
            s.exercise("fs-read", {"r", "w"})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-rights-exceeded")


class ExposeRouting(unittest.TestCase):
    def test_expose_routed_with_matching_endowment(self):
        spec = _spec("child-a", "c-a", _manifest(
            expose=[{"capability": "metrics", "rights": ["r"],
                      "from": "self"}]))
        s = _sup("sup-er", [spec],
                 {"metrics": {"rights": {"r"}, "held": "route",
                              "from": "child-a"}})
        self.assertEqual(
            s.exposed_routing(),
            {"child-a": {"metrics": {"status": "routed",
                                     "rights": ["r"]}}})

    def test_expose_terminates_without_route(self):
        spec = _spec("child-a", "c-a", _manifest(
            expose=[{"capability": "debug", "rights": ["r"],
                      "from": "self"}]))
        s = _sup("sup-et", [spec], {"fs-read": {"r"}})
        self.assertEqual(
            s.exposed_routing(),
            {"child-a": {"debug": {"status": "terminated",
                                   "rights": ["r"]}}})

    def test_expose_wider_than_routed_refused(self):
        spec = _spec("child-a", "c-a", _manifest(
            expose=[{"capability": "metrics", "rights": ["r", "w"],
                      "from": "self"}]))
        with self.assertRaises(sup.SupervisionError) as cm:
            _sup("sup-ew", [spec],
                 {"metrics": {"rights": {"r"}, "held": "route",
                              "from": "child-a"}})
        self.assertEqual(cm.exception.code,
                         "supervision-capability-rights-exceeded")


class GrantsAndRestart(unittest.TestCase):
    def _report(self, child_seed, child_id, reason, crashed_at):
        body = {"child_id": child_id, "reason_kind": "exit",
                "reason_bytes": reason, "crashed_at": crashed_at}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode()
        rep = dict(body)
        rep["signature"] = ed25519.sign(child_seed, raw).hex()
        return rep

    def test_grant_exact(self):
        spec = _spec("child-a", "c-a", _manifest(
            use=[_use("fs-read", ["r"], "parent"),
                 _use("mem", ["w"], "self")]))
        s = _sup("sup-ge", [spec], {"fs-read": {"r", "w"}})
        self.assertEqual(s.granted_capabilities("child-a"),
                         {"fs-read": ["r"], "mem": ["w"]})

    def test_grant_undeclared_child_refused(self):
        s = _sup("sup-gu", [_spec("child-a", "c-a")], None)
        with self.assertRaises(sup.SupervisionError) as cm:
            s.granted_capabilities("ghost")
        self.assertEqual(cm.exception.code, "supervision-undeclared-child")

    def test_restart_carries_capability_grants(self):
        cseed = _seed("c-a")
        spec = sup.ChildSpec("child-a", _pub(cseed), "one_for_one",
                             100, 3600, capabilities=_manifest(
                                 use=[_use("fs-read", ["r"], "parent")]))
        s = _sup("sup-rg", [spec], {"fs-read": {"r", "w"}})
        decision = s.report_crash(
            "child-a", self._report(cseed, "child-a", "boom", 10), at=10)
        self.assertEqual(decision["capability_grants"],
                         {"child-a": {"fs-read": ["r"]}})

    def test_plain_decisions_unchanged(self):
        cseed = _seed("c-b")
        spec = sup.ChildSpec("child-b", _pub(cseed), "one_for_one",
                             100, 3600)
        s = _sup("sup-pd", [spec], None)
        decision = s.report_crash(
            "child-b", self._report(cseed, "child-b", "boom", 10), at=10)
        self.assertNotIn("capability_grants", decision)
        self.assertNotIn("lease_obligations", decision)


class Ed25519Contract(unittest.TestCase):
    def test_verify_true_false(self):
        s = _seed("s")
        pub = ed25519.publickey(s)
        msg = b"contract"
        self.assertIs(ed25519.verify(pub, msg, ed25519.sign(s, msg)), True)
        self.assertIs(
            ed25519.verify(pub, msg, ed25519.sign(_seed("other"), msg)),
            False)


if __name__ == "__main__":
    unittest.main()
