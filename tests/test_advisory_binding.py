"""Unit tests for gov/advisory_binding (W244-6).

Advisory-bound verifier inputs: unscoped pins grade asserted,
advisory snapshots are pinned under a named policy, supersession
picks the newest version, and package checks fail closed on
unavailability, staleness, sub-threshold advisory signatures, and
advisory flags.
"""

import base64
import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gov import advisory_binding as ab
from gov import decision_codes
from gov import ed25519 as e

T_FETCH = 1727731200
T_NOW = T_FETCH + 1800
T_STALE = T_FETCH + 7200

_SEEDS = [bytes([0xA0 + i]) * 32 for i in range(4)]
_PUBS = [e.publickey(s) for s in _SEEDS]


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _policy(**over):
    p = {
        "advisory_policy_input": "advisory-policy-v1",
        "freshness_seconds": 3600,
        "signature_threshold": 3,
        "trusted_keys": [_b64(x) for x in _PUBS],
    }
    p.update(over)
    return p


def _snapshot(version, flags, n_sigs=3, **over):
    body = {"advisory_id": "GHSA-w356-2hw3-x2v2", "version": version,
            "issuer": "zerkerlabs/treeship", "fetched_at": T_FETCH,
            "flags": flags}
    body.update(over)
    canon = _canon(body)
    sigs = [{"key": _b64(_PUBS[i]),
             "sig": _b64(e.sign(_SEEDS[i], canon))}
            for i in range(n_sigs)]
    return {"advisory_id": body["advisory_id"], "version": version,
            "issuer": body["issuer"], "fetched_at": body["fetched_at"],
            "flags": flags, "canonical_bytes": canon,
            "digest": hashlib.sha256(canon).hexdigest(),
            "signatures": sigs}


def _bind(version=2, flags=None):
    return ab.bind_advisory_input(
        _policy(), _snapshot(version, flags or {}), T_NOW)


class PinGradingTest(unittest.TestCase):
    def test_unscoped_pin_grades_asserted(self):
        self.assertEqual(ab.grade_agent_pin({"kind": "agent_cert"}),
                         "asserted")

    def test_scoped_pin_grades_key_bound(self):
        self.assertEqual(ab.grade_agent_pin(
            {"kind": "agent_cert", "agent": "agent://deployer"}),
            "key-bound")

    def test_asserted_pin_refused_as_evidence(self):
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.assert_pin_for_verification({"kind": "agent_cert"})
        self.assertEqual(ctx.exception.code, "pin-scope-insufficient")

    def test_key_bound_pin_passes(self):
        self.assertEqual(ab.assert_pin_for_verification(
            {"kind": "agent_cert", "agent": "agent://deployer"}),
            "key-bound")

    def test_malformed_pin(self):
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.grade_agent_pin({"kind": "not_a_cert"})
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")
        with self.assertRaises(ab.AdvisoryBindingError):
            ab.grade_agent_pin("nope")


class BindTest(unittest.TestCase):
    def test_happy_path(self):
        pinned = _bind()
        self.assertEqual(pinned["version"], 2)
        self.assertEqual(pinned["valid_signatures"], 3)
        self.assertEqual(pinned["advisory_policy_input"],
                         "advisory-policy-v1")

    def test_digest_tamper_refused(self):
        snap = _snapshot(2, {})
        tampered = dict(snap)
        tampered["canonical_bytes"] = b"tampered" + snap["canonical_bytes"]
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.bind_advisory_input(_policy(), tampered, T_NOW)
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")

    def test_rogue_key_not_counted(self):
        snap = _snapshot(2, {}, n_sigs=3)
        rogue = bytes([0xFF]) * 32
        rogue_pub = e.publickey(rogue)
        snap["signatures"][0] = {
            "key": _b64(rogue_pub),
            "sig": _b64(e.sign(rogue, snap["canonical_bytes"]))}
        pinned = ab.bind_advisory_input(_policy(), snap, T_NOW)
        self.assertEqual(pinned["valid_signatures"], 2)

    def test_double_counted_key_counts_once(self):
        snap = _snapshot(2, {}, n_sigs=3)
        snap["signatures"].append(dict(snap["signatures"][0]))
        pinned = ab.bind_advisory_input(_policy(), snap, T_NOW)
        self.assertEqual(pinned["valid_signatures"], 3)

    def test_bool_fetched_at_rejected(self):
        snap = _snapshot(2, {}, fetched_at=True)
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.bind_advisory_input(_policy(), snap, T_NOW)
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")

    def test_bad_flag_value_rejected(self):
        snap = _snapshot(2, {"pkg": "maybe"})
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.bind_advisory_input(_policy(), snap, T_NOW)
        self.assertEqual(ctx.exception.code, "verifier-input-malformed")

    def test_ed25519_verify_bool_contract(self):
        # Pin the bool-return contract (wave-243 lesson): verify returns
        # exactly True/False and never raises.
        self.assertIs(e.verify(_PUBS[0], b"m",
                             e.sign(_SEEDS[0], b"m")),
                      True)
        self.assertIs(e.verify(_PUBS[0], b"m", b"\x00" * 64), False)


class CheckPackageTest(unittest.TestCase):
    def test_unavailable_fails_closed(self):
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.check_package(None, "pkg", T_NOW)
        self.assertEqual(ctx.exception.code, "chain-source-unavailable")

    def test_stale_snapshot_explicit(self):
        pinned = _bind()
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.check_package(pinned, "pkg", T_STALE)
        self.assertEqual(ctx.exception.code, "chain-source-stale")

    def test_threshold_unmet(self):
        snap = _snapshot(2, {}, n_sigs=1)
        pinned = ab.bind_advisory_input(_policy(), snap, T_NOW)
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.check_package(pinned, "pkg", T_NOW)
        self.assertEqual(ctx.exception.code, "registry-threshold-unmet")

    def test_flagged_refused_despite_valid_signature(self):
        pinned = _bind(flags={"pkg-evil": "flagged"})
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.check_package(pinned, "pkg-evil", T_NOW)
        self.assertEqual(ctx.exception.code, "package-advisory-flagged")

    def test_clear_package(self):
        pinned = _bind(flags={"pkg-good": "allow"})
        res = ab.check_package(pinned, "pkg-good", T_NOW)
        self.assertEqual(res["verdict"], "advisory-clear")
        self.assertEqual(res["advisory_policy_input"],
                         "advisory-policy-v1")
        # An unlisted package is not flagged: clear.
        res2 = ab.check_package(pinned, "pkg-unknown", T_NOW)
        self.assertEqual(res2["verdict"], "advisory-clear")


class SupersedeTest(unittest.TestCase):
    def test_newest_wins(self):
        v1 = _bind(version=1, flags={"pkg-x": "allow"})
        v2 = _bind(version=2, flags={"pkg-x": "flagged"})
        effective = ab.supersede([v1, v2])
        self.assertEqual(effective["version"], 2)
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.check_package(effective, "pkg-x", T_NOW)
        self.assertEqual(ctx.exception.code, "package-advisory-flagged")

    def test_empty_set_fails_closed(self):
        with self.assertRaises(ab.AdvisoryBindingError) as ctx:
            ab.supersede([])
        self.assertEqual(ctx.exception.code, "chain-source-unavailable")


class TaxonomyMappingTest(unittest.TestCase):
    def test_new_codes_mapped(self):
        for code in ("package-advisory-flagged", "pin-scope-insufficient"):
            entry = decision_codes.code_for(code)
            self.assertEqual(entry["code"], code)
            self.assertEqual(entry["domain"], "advisory")


if __name__ == "__main__":
    unittest.main()
