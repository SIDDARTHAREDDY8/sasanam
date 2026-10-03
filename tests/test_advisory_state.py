"""Unit tests for gov/advisory_state (W246-6).

Flaw-granular advisory state: a component version answers
affected-by [CVEs] / clean-for [CVEs] / unknown -- never a bare
clean. Wired to gov.advisory_binding.bind_advisory_input.
"""

import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import advisory_state as st
from gov import decision_codes

_T_FETCH = 1727731200
_T_NOW = _T_FETCH + 1800
_T_STALE = _T_FETCH + 7200

_SEEDS = [bytes([0xC0 + i]) * 32 for i in range(2)]

try:
    from gov import ed25519 as _e
    _PUBS = [_e.publickey(s) for s in _SEEDS]
except ImportError:  # pragma: no cover
    _e = None
    _PUBS = []


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _flaws():
    return [
        {"cve": "CVE-2026-102267", "component": "pyjwt",
         "affected": "<2.14.0", "fixed_in": "2.14.0"},
        {"cve": "CVE-2026-101918", "component": "pyjwt",
         "affected": "<=2.14.0", "fixed_in": None},
    ]


def _bind(flaws=None, fetched_at=_T_FETCH, now=_T_NOW):
    flaws = _flaws() if flaws is None else flaws
    policy = {
        "advisory_policy_input": "advisory-policy-v1",
        "freshness_seconds": 3600,
        "signature_threshold": 2,
        "trusted_keys": [_b64(p) for p in _PUBS],
    }
    body = {"advisory_id": "pyjwt-flaw-advisory", "version": 3,
            "issuer": "test-issuer", "fetched_at": fetched_at,
            "flags": {}, "flaws": flaws}
    canon = _canon(body)
    sigs = [{"key": _b64(_PUBS[i]),
             "sig": _b64(_e.sign(_SEEDS[i], canon))}
            for i in range(2)]
    snapshot = dict(body)
    snapshot.update({"canonical_bytes": canon,
                     "digest": hashlib.sha256(canon).hexdigest(),
                     "signatures": sigs})
    return st.bind_flaw_snapshot(policy, snapshot, now)


class TaxonomyPinTest(unittest.TestCase):
    def test_pin_896(self):
        # Wave-246 lane 6: 895 (wave-245 merge) + 1 additive
        # (advisory-input-malformed). Additive only; the merge
        # coordinator repoints the global pins.
        # Wave-246 merge: re-pointed lane-local pin to the composed 936 (was lane-local 896); additive only.
        # Wave-255 lane 4: re-pointed to 1036 (1029 + 7 inventory-catalog), additive
        # only; merge coordinator composed.
        self.assertEqual(len(decision_codes.TAXONOMY), 1753)  # Wave-270 merge: pin 1325 -> 1344 (+19 ptgrant-*: 2 ifc-* + 11 ceremony-v2-* + 19 ptgrant-* + 1 evcert-provisioner-policy-violated + 6 bundlescan-* + 8 evbundle-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*)
        # Wave-250 merge: re-pointed to 997 (979 + 18 wave-250 codes), additive only; merge coordinator composed.

    def test_new_code_resolves(self):
        entry = decision_codes.code_for("advisory-input-malformed")
        self.assertEqual(entry["code"], "advisory-input-malformed")
        self.assertEqual(entry["domain"], "advisory")


class AssessTest(unittest.TestCase):
    def test_pyjwt_2140_affected_by_open_cve(self):
        ans = st.assess_component(_bind(), "pyjwt", "2.14.0", _T_NOW)
        self.assertEqual(ans["state"], "affected-by")
        self.assertEqual(ans["cves"], ["CVE-2026-101918"])
        self.assertEqual(ans["clean_for"], ["CVE-2026-102267"])
        self.assertNotEqual(ans["state"], "clean")

    def test_pyjwt_2130_affected_by_both(self):
        ans = st.assess_component(_bind(), "pyjwt", "2.13.0", _T_NOW)
        self.assertEqual(ans["state"], "affected-by")
        self.assertEqual(ans["cves"],
                         ["CVE-2026-102267", "CVE-2026-101918"])

    def test_clean_for_lists_cves_explicitly(self):
        flaws = [
            {"cve": "CVE-2026-102267", "component": "pyjwt",
             "affected": "<2.14.0", "fixed_in": "2.14.0"},
        ]
        ans = st.assess_component(_bind(flaws=flaws), "pyjwt",
                                  "2.15.0", _T_NOW)
        self.assertEqual(ans["state"], "clean-for")
        self.assertEqual(ans["cves"], ["CVE-2026-102267"])
        self.assertNotEqual(ans["state"], "clean")

    def test_untracked_component_unknown(self):
        ans = st.assess_component(_bind(), "nope", "1.0.0", _T_NOW)
        self.assertEqual(ans["state"], "unknown")
        self.assertEqual(ans["reason"], "component-not-tracked")

    def test_untracked_version_unknown(self):
        ans = st.assess_component(_bind(), "pyjwt", "9.9.9", _T_NOW)
        self.assertEqual(ans["state"], "unknown")
        self.assertEqual(ans["reason"], "version-not-covered")

    def test_unparseable_version_unknown(self):
        ans = st.assess_component(_bind(), "pyjwt", "abc", _T_NOW)
        self.assertEqual(ans["state"], "unknown")
        self.assertEqual(ans["reason"], "version-not-evaluable")

    def test_stale_refuses(self):
        pinned = _bind()
        with self.assertRaises(st.AdvisoryStateError) as cm:
            st.assess_component(pinned, "pyjwt", "2.14.0", _T_STALE)
        self.assertEqual(cm.exception.code, "chain-source-stale")

    def test_malformed_query_refuses(self):
        pinned = _bind()
        with self.assertRaises(st.AdvisoryStateError) as cm:
            st.assess_component(pinned, "", "2.14.0", _T_NOW)
        self.assertEqual(cm.exception.code, "verifier-input-malformed")

    def test_post_signing_flaw_swap_refuses(self):
        # The flaw list presented at bind must be the signed one.
        flaws = _flaws()
        policy = {
            "advisory_policy_input": "advisory-policy-v1",
            "freshness_seconds": 3600,
            "signature_threshold": 2,
            "trusted_keys": [_b64(p) for p in _PUBS],
        }
        body = {"advisory_id": "x", "version": 1, "issuer": "t",
                "fetched_at": _T_FETCH, "flags": {}, "flaws": flaws}
        canon = _canon(body)
        sigs = [{"key": _b64(_PUBS[i]),
                 "sig": _b64(_e.sign(_SEEDS[i], canon))}
                for i in range(2)]
        snapshot = dict(body)
        snapshot.update({"canonical_bytes": canon,
                         "digest": hashlib.sha256(canon).hexdigest(),
                         "signatures": sigs})
        # Swap the flaws AFTER signing: bind must refuse.
        snapshot["flaws"] = [
            {"cve": "CVE-2026-999999", "component": "pyjwt",
             "affected": "<99.0.0", "fixed_in": None},
        ]
        with self.assertRaises(st.AdvisoryStateError) as cm:
            st.bind_flaw_snapshot(policy, snapshot, _T_NOW)
        self.assertEqual(cm.exception.code,
                         "advisory-input-malformed")

    def test_version_compare_padding(self):
        # "2.14" == "2.14.0" for comparison purposes.
        self.assertEqual(st._cmp((2, 14), (2, 14, 0)), 0)
        self.assertEqual(st._cmp((2, 9), (2, 14, 0)), -1)

    def test_multi_clause_spec(self):
        flaws = [
            {"cve": "CVE-2026-222222", "component": "pyjwt",
             "affected": ">=2.0.0, <2.14.0", "fixed_in": "2.14.0"},
        ]
        pinned = _bind(flaws=flaws)
        ans = st.assess_component(pinned, "pyjwt", "2.13.0", _T_NOW)
        self.assertEqual(ans["state"], "affected-by")
        ans = st.assess_component(pinned, "pyjwt", "1.9.0", _T_NOW)
        # 1.9.0 is outside the claimed range with a published fix it
        # does not include: no affirmative clean -> unknown.
        self.assertEqual(ans["state"], "unknown")


if __name__ == "__main__":
    unittest.main()
