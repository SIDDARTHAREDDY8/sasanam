"""Unit tests for gov.bundle_scan (wave-270) and its admission seam.

Scan-without-load pins: the scanner must detect hostile globals and
must NEVER execute payload bytes. The never-executes pin uses a
payload whose unpickling would create a sentinel file via
``os.system``; the test asserts detection AND sentinel absence.

Taxonomy pins are lane-local: 1325 -> 1331 (+6 bundlescan-*). The
global pin (tests/test_decision_codes.py) is repointed by the merge
coordinator.
"""

import os
import pickle
import tempfile
import unittest

from gov import bundle_scan
from gov import decision_codes as dc

TAXONOMY_PIN = 1990 # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-302 merge: pin 1812 -> 1820 (+8 codes: 3 workflow-composed-* + 3 workflow-branch-* + 2 workflow-approval-*); Wave-303 merge: pin 1823 -> 1826 (+6 codes: 1 workflow-idempotency-caller-mismatch +2 workflow-saga-operator-unauthorized/resolution-invalid +3 authority-lifecycle-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-315 lane 2: pin 1878 -> 1888 (+10 vsa-packet-*); Wave-316 lane 4: pin 1888 -> 1900 (+12 transform-*); Wave-318 merge: pin 1900 -> 1906 (+6 trust-root-*); Wave-319 lane 3: pin 1906 -> 1916 (+10 witness-*); Wave-319 merge: pin 1906 -> 1933 (+27: 9 grantneg-* +8 identity-* +10 witness-*); Wave-320 lane 2: pin 1933 -> 1934 (+1 grantneg-registry-withdrawn)

EXPECTED_CODES = [
    "bundlescan-malformed",
    "bundlescan-odd-packaging",
    "bundlescan-oversized",
    "bundlescan-rce-global",
    "bundlescan-suspicious-global",
    "bundlescan-unknown-global",
]

_SENTINEL = "/var/tmp/g270bscan-unit-sentinel"


class _Boom(object):
    def __reduce__(self):
        import os as _os
        return (_os.system, ("touch " + _SENTINEL,))


class _Widget(object):
    pass


class ScanVerdictTests(unittest.TestCase):
    def test_benign_plain_pickle_is_clean(self):
        v = bundle_scan.scan_pickle_stream(
            pickle.dumps({"a": [1, 2, 3]}, protocol=2))
        self.assertEqual(v["verdict"], "clean")
        self.assertIsNone(v["code"])
        self.assertEqual(v["severity"], "none")
        self.assertEqual(v["findings"], [])

    def test_benign_datetime_pickle_is_clean(self):
        import datetime
        v = bundle_scan.scan_pickle_stream(
            pickle.dumps(datetime.datetime(2026, 1, 1), protocol=2))
        self.assertEqual(v["verdict"], "clean")
        self.assertIsNone(v["code"])

    def test_os_system_reduce_refuses_critical(self):
        import os as _os
        data = pickle.dumps(_os.system, protocol=2)  # noqa -- never unpickled
        v = bundle_scan.scan_pickle_stream(
            pickle.dumps(
                type("X", (), {"__reduce__": lambda self: (_os.system,
                                                           ("x",))})(),
                protocol=2))
        self.assertEqual(v["verdict"], "refuse")
        self.assertEqual(v["code"], "bundlescan-rce-global")
        self.assertEqual(v["severity"], "critical")
        self.assertTrue(any(f["severity"] == "critical"
                            for f in v["findings"]))
        self.assertFalse(os.path.exists(_SENTINEL))

    def test_never_executes_pin(self):
        # The payload would create _SENTINEL via os.system if
        # unpickled. The scanner must refuse AND the sentinel must not
        # exist afterwards.
        if os.path.exists(_SENTINEL):
            os.unlink(_SENTINEL)
        data = pickle.dumps(_Boom(), protocol=2)
        v = bundle_scan.scan_pickle_stream(data)
        self.assertEqual(v["verdict"], "refuse")
        self.assertEqual(v["code"], "bundlescan-rce-global")
        self.assertFalse(os.path.exists(_SENTINEL),
                         "scanner executed payload bytes")

    def test_builtin_eval_normalized_and_refused(self):
        class _E(object):
            def __reduce__(self):
                return (eval, ("1+1",))
        v = bundle_scan.scan_pickle_stream(pickle.dumps(_E(), protocol=2))
        self.assertEqual(v["verdict"], "refuse")
        self.assertEqual(v["code"], "bundlescan-rce-global")

    def test_subprocess_popen_stack_global_refused(self):
        class _P(object):
            def __reduce__(self):
                import subprocess
                return (subprocess.Popen, (["x"],))
        v = bundle_scan.scan_pickle_stream(pickle.dumps(_P(), protocol=4))
        self.assertEqual(v["verdict"], "refuse")
        self.assertEqual(v["code"], "bundlescan-rce-global")

    def test_sink_without_reduce_is_high_advisory(self):
        v = bundle_scan.scan_pickle_stream(pickle.dumps(eval, protocol=2))
        self.assertEqual(v["verdict"], "advisory")
        self.assertEqual(v["code"], "bundlescan-suspicious-global")
        self.assertEqual(v["severity"], "high")

    def test_getattr_gadget_is_high_advisory(self):
        v = bundle_scan.scan_pickle_stream(pickle.dumps(getattr, protocol=2))
        self.assertEqual(v["verdict"], "advisory")
        self.assertEqual(v["code"], "bundlescan-suspicious-global")
        self.assertEqual(v["severity"], "high")

    def test_unknown_custom_global_is_medium_advisory(self):
        v = bundle_scan.scan_pickle_stream(
            pickle.dumps(_Widget(), protocol=2))
        self.assertEqual(v["verdict"], "advisory")
        self.assertEqual(v["code"], "bundlescan-unknown-global")
        self.assertEqual(v["severity"], "medium")

    def test_trailing_bytes_are_low_advisory(self):
        data = pickle.dumps({"a": 1}, protocol=2) + b"TRAILER"
        v = bundle_scan.scan_pickle_stream(data)
        self.assertEqual(v["verdict"], "advisory")
        self.assertEqual(v["code"], "bundlescan-odd-packaging")
        self.assertEqual(v["severity"], "low")

    def test_truncated_stream_fails_closed(self):
        data = pickle.dumps({"a": [1, 2]}, protocol=2)
        for bad in (data[:10], b"", b"\x80", b"not a pickle at all!!"):
            v = bundle_scan.scan_pickle_stream(bad)
            self.assertEqual(v["verdict"], "refuse", bad)
            self.assertEqual(v["code"], "bundlescan-malformed")

    def test_non_bytes_fails_closed(self):
        for bad in ("x", 42, None, ["x"]):
            v = bundle_scan.scan_pickle_stream(bad)
            self.assertEqual(v["verdict"], "refuse")
            self.assertEqual(v["code"], "bundlescan-malformed")

    def test_oversized_refused_before_parsing(self):
        data = pickle.dumps({"a": 1}, protocol=2)
        v = bundle_scan.scan_pickle_stream(data, max_bytes=4)
        self.assertEqual(v["verdict"], "refuse")
        self.assertEqual(v["code"], "bundlescan-oversized")

    def test_deterministic(self):
        data = pickle.dumps({"a": [1, 2]}, protocol=2)
        a = bundle_scan.scan_pickle_stream(data)
        b = bundle_scan.scan_pickle_stream(data)
        self.assertEqual(a, b)

    def test_verdict_shape(self):
        v = bundle_scan.scan_pickle_stream(pickle.dumps(1, protocol=2))
        self.assertEqual(set(v.keys()),
                         {"verdict", "code", "severity", "findings",
                          "evidence_digest", "payload_bytes",
                          "out_of_scope"})
        self.assertEqual(len(v["evidence_digest"]), 64)
        self.assertEqual(v["payload_bytes"],
                         len(pickle.dumps(1, protocol=2)))
        self.assertTrue(v["out_of_scope"])


class AdmissionSeamTests(unittest.TestCase):
    def _admission_bits(self):
        import hashlib
        from gov import ed25519, skill_admission
        auth_seed = hashlib.sha256(b"g270-unit-authority").digest()
        step_seed = hashlib.sha256(b"g270-unit-step").digest()
        auth_pub = ed25519.publickey(auth_seed).hex()
        step_pub = ed25519.publickey(step_seed).hex()
        layout = skill_admission.make_layout(
            "g270-unit", [{"name": "build", "command": ["make"],
                           "signer_pub": step_pub,
                           "rules": [("DISALLOW",)]}],
            auth_seed)
        link = skill_admission.make_link(
            "g270-unit", "build", ["make"], {}, {}, step_seed)
        return skill_admission, layout, [link], auth_pub

    def test_legacy_admit_has_no_content_scan_key(self):
        sa, layout, links, auth_pub = self._admission_bits()
        v = sa.admit(layout, links, auth_pub)
        self.assertTrue(v["admitted"])
        self.assertNotIn("content_scan", v["evidence"])

    def test_critical_payload_refuses_with_identity(self):
        sa, layout, links, auth_pub = self._admission_bits()
        data = pickle.dumps(_Boom(), protocol=2)
        v = sa.admit(layout, links, auth_pub,
                     artifact_bytes={"model.pkl": data})
        self.assertFalse(v["admitted"])
        self.assertEqual(v["code"], "bundlescan-rce-global")
        scan = v["evidence"]["content_scan"]
        self.assertEqual(scan["verdict"], "refuse")
        arts = [a["artifact"] for a in scan["advisories"]]
        self.assertIn("model.pkl", arts)

    def test_advisory_payload_still_admits_with_evidence(self):
        sa, layout, links, auth_pub = self._admission_bits()
        data = pickle.dumps(_Widget(), protocol=2)
        v = sa.admit(layout, links, auth_pub,
                     artifact_bytes={"model.pkl": data})
        self.assertTrue(v["admitted"])
        scan = v["evidence"]["content_scan"]
        self.assertEqual(scan["verdict"], "advisory")
        arts = [a["artifact"] for a in scan["advisories"]]
        self.assertIn("model.pkl", arts)

    def test_benign_payload_admits_clean(self):
        sa, layout, links, auth_pub = self._admission_bits()
        data = pickle.dumps({"weights": [1.0]}, protocol=2)
        v = sa.admit(layout, links, auth_pub,
                     artifact_bytes={"model.pkl": data})
        self.assertTrue(v["admitted"])
        scan = v["evidence"]["content_scan"]
        self.assertEqual(scan["verdict"], "clean")
        self.assertIn("model.pkl", scan["scanned"])

    def test_malformed_artifact_bytes_arg_is_refused(self):
        # admit() never raises on adversarial input: a malformed
        # artifact_bytes argument is a refused verdict with the
        # layout-malformed code, not an exception.
        from gov import skill_admission
        sa, layout, links, auth_pub = self._admission_bits()
        v = sa.admit(layout, links, auth_pub,
                     artifact_bytes=["model.pkl"])
        self.assertFalse(v["admitted"])
        self.assertEqual(v["code"],
                         skill_admission.SKILL_ADMISSION_LAYOUT_MALFORMED)


class TaxonomyPinTests(unittest.TestCase):
    def test_six_codes_registered_and_pin(self):
        for code in EXPECTED_CODES:
            self.assertIn(code, dc.TAXONOMY)
        self.assertEqual(len(dc.TAXONOMY), TAXONOMY_PIN)

    def test_code_literals_unique_in_source(self):
        # Wave-260 lesson: assert on raw source literals, never
        # len(dict) -- a duplicated block is invisible to the dict.
        import gov.decision_codes as mod
        src = open(mod.__file__).read()
        for code in EXPECTED_CODES:
            self.assertEqual(
                src.count('"code": %r' % (code,)), 1,
                "code literal %s not unique in source" % (code,))
            self.assertEqual(
                src.count("'%s': {" % (code,)), 1,
                "dict key %s not unique in source" % (code,))

    def test_codes_sorted_in_source(self):
        import gov.decision_codes as mod
        src = open(mod.__file__).read()
        positions = [src.index("'%s': {" % (c,)) for c in EXPECTED_CODES]
        self.assertEqual(positions, sorted(positions))


if __name__ == "__main__":
    unittest.main()
