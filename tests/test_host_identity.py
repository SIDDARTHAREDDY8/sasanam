"""Unit tests for gov/host_identity.py (W241-1, treeship N-41 steal).

All expected values are independent literals (worked examples), never
recomputed the way the code does. The digest literals below are the
sha256/sha1 hex of the literal hostname "db-primary-07", precomputed
outside the module under test.
"""

import hashlib
import os
import stat
import tempfile
import threading
import unittest

from gov import host_identity as hi
from gov import decision_codes as dc

# Worked examples: literals only.
_GOOD_ID = "host_0123456789abcdef"
_HOST = "db-primary-07"
_HOST_SHA256 = "c70f6b09f947b80580b676f80f4d7d18987454944d1ac88dd2f7a97b9bea2b53"
_HOST_SHA1 = "daaab3da9fc655a96096e328de9fcdb4e07aba89"


class TestShapeValidation(unittest.TestCase):
    def test_canonical_shape_validates(self):
        self.assertEqual(hi.validate_host_identity(_GOOD_ID,
                                                   hostname=_HOST),
                         _GOOD_ID)

    def test_malformed_shapes_refuse(self):
        for bad in ("HOST_0123456789abcdef",   # uppercase prefix
                    "host_0123456789abcde",    # 15 hex
                    "host_0123456789abcdef0",  # 17 hex
                    "host_0123456789abcdeg",  # non-hex
                    "host_unknown",            # fallback is not a minted id
                    "db-primary-08",           # another hostname-shaped str
                    "", None, 42):
            with self.subTest(bad=bad):
                with self.assertRaises(hi.HostIdentityError) as ctx:
                    hi.validate_host_identity(bad, hostname=_HOST)
                self.assertEqual(ctx.exception.code,
                                 "hostid-malformed-identity")

    def test_hostname_refused_with_named_code(self):
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.validate_host_identity(_HOST, hostname=_HOST)
        self.assertEqual(ctx.exception.code, "hostid-hostname-not-identity")

    def test_hostname_digests_refused_with_named_code(self):
        # Sanity: literals really are the digests of the literal host.
        self.assertEqual(hashlib.sha256(_HOST.encode()).hexdigest(),
                         _HOST_SHA256)
        self.assertEqual(hashlib.sha1(_HOST.encode()).hexdigest(), _HOST_SHA1)
        for digest in (_HOST_SHA256, _HOST_SHA1):
            with self.subTest(digest=digest[:12]):
                with self.assertRaises(hi.HostIdentityError) as ctx:
                    hi.validate_host_identity(digest, hostname=_HOST)
                self.assertEqual(ctx.exception.code,
                                 "hostid-hostname-digest-not-identity")


class TestMinting(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hostid-unit-")
        self.path = os.path.join(self.tmp, "host_id")

    def test_mint_stable_and_0600_regular(self):
        first = hi.mint_host_id(self.path)
        self.assertTrue(hi.HOST_ID_PATTERN.match(first))
        self.assertEqual(hi.mint_host_id(self.path), first)
        st = os.lstat(self.path)
        self.assertTrue(stat.S_ISREG(st.st_mode))
        self.assertFalse(stat.S_ISLNK(st.st_mode))
        self.assertEqual(stat.S_IMODE(st.st_mode), 0o600)
        self.assertEqual(hi.read_host_id(self.path), first)

    def test_mint_entropy_differs_across_dirs(self):
        a = hi.mint_host_id(os.path.join(self.tmp, "a", "host_id"))
        b = hi.mint_host_id(os.path.join(self.tmp, "b", "host_id"))
        self.assertNotEqual(a, b)

    def test_concurrent_mint_same_id(self):
        barrier = threading.Barrier(3)
        seen = []

        def worker():
            barrier.wait()
            seen.append(hi.mint_host_id(self.path))

        threads = [threading.Thread(target=worker) for _ in range(2)]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join()
        self.assertEqual(seen[0], seen[1])

    def test_symlink_at_id_path_refused(self):
        real = os.path.join(self.tmp, "real")
        with open(real, "w") as fh:
            fh.write(_GOOD_ID)
        link = os.path.join(self.tmp, "link_id")
        os.symlink(real, link)
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.mint_host_id(link)
        self.assertEqual(ctx.exception.code, "hostid-symlink-at-id-path")
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.read_host_id(link)
        self.assertEqual(ctx.exception.code, "hostid-symlink-at-id-path")

    def test_corrupt_file_refused(self):
        with open(self.path, "w") as fh:
            fh.write("not-an-id")
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.read_host_id(self.path)
        self.assertEqual(ctx.exception.code, "hostid-id-file-corrupt")

    def test_missing_file_refused(self):
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.read_host_id(self.path)
        self.assertEqual(ctx.exception.code, "hostid-id-file-corrupt")

    def test_default_path_shape(self):
        self.assertTrue(
            hi.default_id_path().endswith(
                os.path.join(".sasanam", "host_id")))


class TestReceiptBinding(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hostid-unit-")
        self.minted = hi.mint_host_id(os.path.join(self.tmp, "host_id"))

    def test_receipt_with_minted_id_passes(self):
        self.assertEqual(
            hi.assert_receipt_host_identity({"host_identity": self.minted},
                                            hostname=_HOST),
            self.minted)

    def test_receipt_with_hostname_refused(self):
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.assert_receipt_host_identity({"host_identity": _HOST},
                                            hostname=_HOST)
        self.assertEqual(ctx.exception.code, "hostid-hostname-not-identity")

    def test_receipt_with_hostname_digest_refused(self):
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.assert_receipt_host_identity(
                {"host_identity": _HOST_SHA256}, hostname=_HOST)
        self.assertEqual(ctx.exception.code,
                         "hostid-hostname-digest-not-identity")

    def test_absent_identity_yields_host_unknown(self):
        self.assertEqual(hi.assert_receipt_host_identity({},
                                                        hostname=_HOST),
                         "host_unknown")
        self.assertEqual(hi.assert_receipt_host_identity(
            {"host_identity": None}, hostname=_HOST), "host_unknown")

    def test_non_mapping_receipt_refused(self):
        with self.assertRaises(hi.HostIdentityError) as ctx:
            hi.assert_receipt_host_identity(["host_identity", self.minted],
                                            hostname=_HOST)
        self.assertEqual(ctx.exception.code, "hostid-malformed-identity")


class TestTaxonomyPin(unittest.TestCase):
    def test_pin_766_and_new_codes_mapped(self):
        # Wave-242 merge: re-pointed 766 -> 788 (22 new codes: 5
        # aggregate-budget/no-effect + 6 stale-authority/containment
        # + 1 exception-TTL + 10 absence-epoch), additive only, composed
        # from the five lane commits by direct byte-verification.
        # Wave-243 merge: re-pointed 788 -> 828 (40 additive codes: 2 cosign-interop
        # + 5 finality-bound + 6 transactional-tokens + 4 action-bound-permits
        # + 6 attested-channel + 2 outcome-vocabulary + 5 verifier-failclosed
        # + 10 effect-agreement/registry/mcp), additive only, composed from the
        # eight lane commits by direct byte-verification.
        # Wave-245 merge: re-pointed to 895 (32 additive wave-245 codes: 8 mcp-oauth + 5 spawn-context + 3 registry-acceptance + 7 delegation-freshness + 4 egress-propagation + 5 jwks), additive only, comment + assert.
        # Wave-247 lane 1: re-pointed to 938 (936 + 2 uri-normalize codes: uri-host-invalid, uri-host-unparseable), additive only; merge coordinator recomposes.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(dc.TAXONOMY), 1829)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.
        expected = {
            "hostid-hostname-not-identity": ("hostid", "high"),
            "hostid-hostname-digest-not-identity": ("hostid", "high"),
            "hostid-symlink-at-id-path": ("hostid", "critical"),
            "hostid-id-file-corrupt": ("hostid", "high"),
            "hostid-malformed-identity": ("hostid", "medium"),
        }
        for code, (domain, severity) in expected.items():
            with self.subTest(code=code):
                entry = dc.code_for(code)
                self.assertEqual(entry["domain"], domain)
                self.assertEqual(entry["severity"], severity)


if __name__ == "__main__":
    unittest.main()
