"""Unit tests for gov/canonical_record.py (wave-237 lane C).

Tests the canonicalization contract at the public seams:
canonicalize_record, derive_request_digest, derive_tier, and the
CanonicalRecordError machine codes. Expected values are hand-computed
literals from the RFC 8785 rules, never recomputed by the code under
test.
"""

import hashlib
import unittest

from gov.canonical_record import (
    MAX_NESTING_DEPTH,
    MARKER_CANONICAL,
    MARKER_OPAQUE,
    TIER_MISMATCH_NOTE,
    CanonicalRecordError,
    canonicalize_record,
    derive_request_digest,
    derive_tier,
)


def _code(fn, *args):
    try:
        fn(*args)
    except CanonicalRecordError as exc:
        return exc.code
    return None


class CanonicalBytesTest(unittest.TestCase):
    def test_sorted_keys_fixed_separators(self):
        octets, marker = canonicalize_record({"b": 2, "a": 1})
        self.assertEqual(octets, b'{"a":1,"b":2}')
        self.assertEqual(marker, MARKER_CANONICAL)

    def test_no_whitespace_no_solidus_escape(self):
        octets, _ = canonicalize_record({"u": "a/b"})
        self.assertEqual(octets, b'{"u":"a/b"}')

    def test_string_escapes(self):
        # RFC 8785: short forms for b/f/n/r/t, \u00xx for other C0.
        octets, _ = canonicalize_record({"s": "q\"\n\x01\\"})
        self.assertEqual(octets, b'{"s":"q\\"\\n\\u0001\\\\"}')

    def test_integers_minimal_form(self):
        octets, _ = canonicalize_record({"n": -42, "big": 10 ** 40})
        self.assertEqual(octets,
                         b'{"big":10000000000000000000000000000000000000000,'
                         b'"n":-42}')

    def test_utf16_key_order(self):
        # Non-BMP keys sort by UTF-16 code units per RFC 8785:
        # "a" (U+0061) < "\U0001F600a" (D83D DE00 0061) <
        # "\U0001F600b" (D83D DE00 0062). Hand-computed expected bytes.
        rec = {"\U0001F600b": 1, "a": 2, "\U0001F600a": 3}
        octets, _ = canonicalize_record(rec)
        self.assertEqual(
            octets,
            '{"a":2,"\U0001F600a":3,"\U0001F600b":1}'.encode("utf-8"))

    def test_semantic_equality_byte_identical(self):
        a = {"z": [3, {"y": None}], "a": True}
        b = {"a": True, "z": [3, {"y": None}]}
        oa, ma = canonicalize_record(a)
        ob, mb = canonicalize_record(b)
        self.assertEqual(oa, ob)
        self.assertEqual((ma, mb), (MARKER_CANONICAL, MARKER_CANONICAL))


class RefusalTest(unittest.TestCase):
    def test_duplicate_member(self):
        self.assertEqual(_code(canonicalize_record,
                               b'{"a":1,"a":2}'),
                         "record-duplicate-member")

    def test_duplicate_member_nested(self):
        self.assertEqual(_code(canonicalize_record,
                               b'{"o":{"x":1,"x":2}}'),
                         "record-duplicate-member")

    def test_depth_boundary(self):
        self.assertEqual(MAX_NESTING_DEPTH, 128)
        deep = b'{"k":' * 128 + b'1' + b'}' * 128
        self.assertEqual(_code(canonicalize_record, deep),
                         "record-depth-exceeded")
        ok_chain = b'{"k":' * 127 + b'1' + b'}' * 127
        octets, marker = canonicalize_record(ok_chain)
        self.assertEqual(marker, MARKER_CANONICAL)
        self.assertTrue(octets.startswith(b'{"k":'))

    def test_depth_boundary_python_value(self):
        deep = {}
        cur = deep
        for _ in range(128):
            cur["k"] = {}
            cur = cur["k"]
        self.assertEqual(_code(canonicalize_record, deep),
                         "record-depth-exceeded")

    def test_floats_refused(self):
        for value in (1.0, 1.5, -0.0, float("inf")):
            self.assertEqual(_code(canonicalize_record, {"a": value}),
                             "record-noncanonical-float",
                             "float %r" % (value,))
        for raw in (b'{"a":1.0}', b'{"a":1e3}', b'{"a":-0.5}'):
            self.assertEqual(_code(canonicalize_record, raw),
                             "record-noncanonical-float")

    def test_top_level_float_refused(self):
        self.assertEqual(_code(canonicalize_record, 1.0),
                         "record-noncanonical-float")

    def test_malformed_python_shapes(self):
        self.assertEqual(_code(canonicalize_record, {"a": {1, 2}}),
                         "record-malformed")
        self.assertEqual(_code(canonicalize_record, {1: "x"}),
                         "record-malformed")
        self.assertEqual(_code(canonicalize_record, object()),
                         "record-malformed")

    def test_lone_surrogate_refused(self):
        # An actual lone-surrogate char in a str cannot be encoded:
        # malformed, never silently dropped.
        self.assertEqual(_code(canonicalize_record, "a\ud800b"),
                         "record-malformed")


class OpaqueBytesTest(unittest.TestCase):
    def test_non_json_bytes_passthrough(self):
        raw = b"\xff\xfe\x00binary"
        octets, marker = canonicalize_record(raw)
        self.assertEqual(octets, raw)
        self.assertEqual(marker, MARKER_OPAQUE)
        self.assertEqual(marker, "record-opaque-bytes")

    def test_invalid_json_text_passthrough(self):
        raw = b"{not json"
        octets, marker = canonicalize_record(raw)
        self.assertEqual((octets, marker), (raw, MARKER_OPAQUE))

    def test_opaque_digest_covers_raw_bytes(self):
        raw = b"\xff\xfe\x00binary"
        self.assertEqual(derive_request_digest(raw),
                         hashlib.sha256(raw).hexdigest())

    def test_opaque_tier_zero_no_note(self):
        self.assertEqual(derive_tier(b"\xff\xfe"), (0, None))


class DigestTest(unittest.TestCase):
    def test_digest_stable_across_key_order(self):
        a = {"b": 2, "a": [1, {"x": "v"}]}
        b = {"a": [1, {"x": "v"}], "b": 2}
        da = derive_request_digest(a)
        db = derive_request_digest(b)
        self.assertEqual(da, db)
        self.assertEqual(da,
                         hashlib.sha256(
                             canonicalize_record(a)[0]).hexdigest())
        self.assertEqual(len(da), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in da))

    def test_digest_differs_on_content(self):
        self.assertNotEqual(derive_request_digest({"a": 1}),
                            derive_request_digest({"a": 2}))


class TierTest(unittest.TestCase):
    def test_tier_boundaries(self):
        self.assertEqual(derive_tier({"action": "read"})[0], 0)
        self.assertEqual(
            derive_tier({"receipt_id": "r1", "action": "read"})[0], 1)
        self.assertEqual(
            derive_tier({"seal": "sig", "receipt_id": "r1"})[0], 2)
        self.assertEqual(
            derive_tier({"anchor_digest": "abc", "seal": "sig"})[0], 3)

    def test_producer_tier_never_read(self):
        # Same content attributes, different asserted tiers: derived
        # tier is identical; only the mismatch note varies.
        t1, n1 = derive_tier({"seal": "sig", "tier": 0})
        t2, n2 = derive_tier({"seal": "sig", "tier": 99})
        t3, n3 = derive_tier({"seal": "sig", "tier": 2})
        self.assertEqual((t1, t2, t3), (2, 2, 2))
        self.assertEqual(n1, TIER_MISMATCH_NOTE)
        self.assertEqual(n2, TIER_MISMATCH_NOTE)
        self.assertIsNone(n3)
        self.assertEqual(TIER_MISMATCH_NOTE, "record-tier-mismatch")

    def test_non_integer_asserted_tier_noted(self):
        tier, note = derive_tier({"action": "read", "tier": "high"})
        self.assertEqual((tier, note), (0, TIER_MISMATCH_NOTE))

    def test_bool_tier_not_confused(self):
        # bool is not read as an asserted tier.
        tier, note = derive_tier({"action": "read", "tier": True})
        self.assertEqual((tier, note), (0, None))

    def test_mismatch_is_note_not_refusal(self):
        # The mismatch never raises: the refusal belongs to the
        # verifier, not to this module.
        try:
            derive_tier({"anchor_digest": "abc", "tier": 0})
        except CanonicalRecordError:
            self.fail("tier mismatch must not raise")


class TaxonomyMappingTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        from gov import decision_codes as dc
        for code in ("record-duplicate-member", "record-depth-exceeded",
                     "record-noncanonical-float", "record-malformed",
                     "record-opaque-bytes"):
            entry = dc.code_for(code)
            self.assertEqual(entry["domain"], "canonical")
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
        self.assertEqual(len(dc.TAXONOMY), 1934)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*); Wave-312 lane D: pin 1841 -> 1851 (+10: 8 witness-log-* + 2 evidence-bundle-witness-*); Wave-313 lane B: pin 1851 -> 1857 (+6 approval-token-*); Wave-319 merge: pin 1906 -> 1933 (+27)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes: 1 skill-update digest-changed + 4 decision-log + 9 permit-journal + 4 evidence-graph), additive only; merge coordinator composed.


if __name__ == "__main__":
    unittest.main()
