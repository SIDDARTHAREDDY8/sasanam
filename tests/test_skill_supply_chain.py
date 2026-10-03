#!/usr/bin/env python3
"""Unit tests for gov.skill_supply_chain (wave-267 lane).

Public-seam tests: seal/verify round-trips, delegation authority
(path scope, first-match-authoritative, threshold counting,
revocation-by-absence, rollback, snapshot binding, pinned eval-start
expiry), lifecycle layouts (link chaining, signer thresholds,
transition rules incl. terminal DISALLOW, layout expiry/signature),
evidence records, and the decision-code taxonomy registration.
Deterministic (fixed seeds, fixed epochs); stdlib-only plus
gov.signing. Run with ~/workspace/.gov-venv/bin/python -m unittest
tests.test_skill_supply_chain.
"""

import base64
import hashlib
import json
import os
import sys
import unittest

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import skill_supply_chain as sc
from gov.bundle_refresh import tuf_canonical_json
from gov.signing import Ed25519Signer

TAXONOMY_PIN = 1797  # Wave-273 merge: pin 1443 -> 1458 (+15 codes: 1 sandbox-* + 10 bundle-delivery-* + 4 egress-ref-*).; Wave-280 merge: pin 1495 -> 1541 (+13 battery-lang-* +1 delegation-ephemeral-grant-refused +32 shield/evaltask-*); Wave-281 lane 9: pin 1541 -> 1551 (+10 guardplugin-*); Wave-283 lane 5: pin 1579 -> 1581 (+2 finding-*).; Wave-283 merge: pin 1581 -> 1587 (+6 inventory-*).; Wave-284 lane 1: pin 1587 -> 1588 (+1 discovery-emit-failed).; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1700 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 merge: pin 1730 -> 1730 (renumber F361->F364, no new codes). Wave-294 merge: pin 1730 -> 1742 (+12: 4 coord-lease-* + 4 toolcall/toolfilter-* + 4 toolcall-schema-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)


def _seed(tag):
    return (tag + "-seed").ljust(32, "0")[:32].encode("ascii")


_R1 = Ed25519Signer(_seed("u-r1"))
_P1 = Ed25519Signer(_seed("u-p1"))
_P2 = Ed25519Signer(_seed("u-p2"))
_M1 = Ed25519Signer(_seed("u-m1"))

EVAL = 1700000000.0
FUTURE = "2030-01-01T00:00:00Z"
PAST = "2020-01-01T00:00:00Z"


def _keyinfo(signer):
    return {"keytype": "ed25519",
            "keyval": {"public": signer.public_key.hex()}}


KEYS = {"r1": _keyinfo(_R1), "pay-k1": _keyinfo(_P1),
        "pay-k2": _keyinfo(_P2), "mallory": _keyinfo(_M1)}

ROOT_TRUST = {"keys": KEYS, "root": {"keyids": ["r1"], "threshold": 1}}


def _seal(kind, doc, pairs):
    return sc.seal_document(kind, doc, pairs)


def _deleg_doc(version, delegations, expires=FUTURE):
    return {"version": version, "expires": expires,
            "delegations": delegations}


def _deleg(name, keyids, threshold, paths, terminating=False):
    return {"name": name, "keyids": keyids, "threshold": threshold,
            "paths": paths, "terminating": terminating}


def _authz(skill, version=1, digest="ab" * 32, expires=FUTURE):
    return {"skill": skill, "version": version, "digest": digest,
            "expires": expires}


def _deleg_wire(version, delegations, expires=FUTURE, signer=("r1", _R1)):
    return _seal("delegations", _deleg_doc(version, delegations, expires),
                 [signer])


def _authz_wire(skill, signers, **kw):
    return _seal("link", _authz(skill, **kw), signers)


_D = {n: hashlib.sha256(("ucontent:" + n).encode()).hexdigest()
      for n in ("bundle.tar.gz", "manifest.json", "unpacked/skill.py",
                "installed.marker")}

_TRANSITIONS = [
    {"name": "publish",
     "signers": {"keyids": ["pay-k1"], "threshold": 1},
     "expected_materials": [],
     "expected_products": [["CREATE", "bundle.tar.gz"],
                           ["REQUIRE", "manifest.json"]]},
    {"name": "fetch",
     "signers": {"keyids": ["pay-k1"], "threshold": 1},
     "expected_materials": [["MATCH", "bundle.tar.gz",
                             _D["bundle.tar.gz"]]],
     "expected_products": [["CREATE", "unpacked/skill.py"]]},
    {"name": "install",
     "signers": {"keyids": ["pay-k1"], "threshold": 1},
     "expected_materials": [["MATCH", "unpacked/skill.py",
                             _D["unpacked/skill.py"]]],
     "expected_products": [["CREATE", "installed.marker"]]},
]


def _layout_wire(expires=FUTURE, signer=("r1", _R1)):
    doc = {"bundle": "skills/payments/x", "version": 1,
           "expires": expires,
           "authority": {"keyids": ["r1"], "threshold": 1},
           "transitions": _TRANSITIONS}
    return _seal("layout", doc, [signer])


def _link(transition, materials, products, prev):
    return {"transition": transition, "materials": materials,
            "products": products, "byproducts": {}, "prev_digest": prev}


def _good_link_wires(signer=("pay-k1", _P1)):
    l0 = _link("publish", {},
               {"bundle.tar.gz": _D["bundle.tar.gz"],
                "manifest.json": _D["manifest.json"]}, "0" * 64)
    h0 = hashlib.sha256(tuf_canonical_json(l0)).hexdigest()
    l1 = _link("fetch", {"bundle.tar.gz": _D["bundle.tar.gz"]},
               {"unpacked/skill.py": _D["unpacked/skill.py"]}, h0)
    h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
    l2 = _link("install", {"unpacked/skill.py": _D["unpacked/skill.py"]},
               {"installed.marker": _D["installed.marker"]}, h1)
    return [_seal("link", l, [signer]) for l in (l0, l1, l2)]


class SealContract(unittest.TestCase):
    def test_seal_round_trip(self):
        doc = {"hello": "world"}
        wire = _seal("delegations", doc, [("r1", _R1)])
        env = json.loads(wire.decode("utf-8"))
        self.assertEqual(env["payloadType"],
                         "application/vnd.sasanam.supplychain-"
                         "delegations+json")
        self.assertEqual(json.loads(base64.b64decode(env["payload"])),
                         doc)

    def test_unknown_kind_refused(self):
        # Programmer error at build time: fail fast, not silently.
        with self.assertRaises(ValueError):
            sc.seal_document("bogus", {}, [("r1", _R1)])

    def test_wrong_payload_type_refused(self):
        wire = _seal("delegations", {"a": 1}, [("r1", _R1)])
        env = json.loads(wire.decode("utf-8"))
        env["payloadType"] = "application/vnd.sasanam.supplychain-nope+json"
        bad = json.dumps(env).encode("utf-8")
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(bad, awire, "skills/payments/x",
                                          ROOT_TRUST, EVAL)
        self.assertEqual(ctx.exception.code,
                         "supplychain-delegation-signature-invalid")

    def test_truncated_wire_refused(self):
        dwire = _deleg_wire(1, [_deleg("t", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire[:40], awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, EVAL)
        self.assertEqual(ctx.exception.code, "supplychain-malformed")

    def test_verify_contract_true_false(self):
        # gov.ed25519.verify returns exact True/False and never raises
        # (wave-243 lesson): assert the contract with `is`, and prove
        # the module honors a False return -- a corrupted signature
        # byte must refuse, not verify.
        from gov import ed25519
        doc = {"a": 1}
        wire = _seal("delegations", doc, [("r1", _R1)])
        env = json.loads(wire.decode("utf-8"))
        pae = sc.pae(env["payloadType"],
                      base64.b64decode(env["payload"]))
        sig = bytes.fromhex(env["signatures"][0]["sig"])
        self.assertIs(ed25519.verify(_R1.public_key, pae, sig), True)
        self.assertIs(ed25519.verify(_R1.public_key, b"tampered", sig),
                      False)
        corrupted = dict(env)
        corrupted["signatures"] = [dict(env["signatures"][0])]
        raw = bytearray(bytes.fromhex(
            corrupted["signatures"][0]["sig"]))
        raw[0] ^= 0x01
        corrupted["signatures"][0]["sig"] = bytes(raw).hex()
        dwire = _deleg_wire(1, [_deleg("t", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        env2 = json.loads(dwire.decode("utf-8"))
        env2["signatures"] = corrupted["signatures"]
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(
                json.dumps(env2).encode("utf-8"), awire,
                "skills/payments/x", ROOT_TRUST, EVAL)
        self.assertEqual(ctx.exception.code,
                         "supplychain-delegation-signature-invalid")


class DelegatedAuthority(unittest.TestCase):
    def _ok(self):
        dwire = _deleg_wire(1, [_deleg("payments-team", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        return dwire, awire

    def test_legit(self):
        dwire, awire = self._ok()
        rep = sc.verify_delegated_authority(dwire, awire,
                                            "skills/payments/x",
                                            ROOT_TRUST, EVAL)
        self.assertTrue(rep["ok"])
        self.assertEqual(rep["delegation"], "payments-team")
        self.assertTrue(rep["checked"])
        self.assertTrue(rep["out_of_scope"])

    def test_distinct_key_threshold_counting(self):
        # Two signatures, same key: counts once -> 2-of-2 fails.
        dwire = _deleg_wire(1, [_deleg("payments-team",
                                       ["pay-k1", "pay-k2"], 2,
                                       ["skills/payments/*"])])
        awire = _authz_wire("skills/payments/x",
                            [("pay-k1", _P1), ("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire, awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, EVAL)
        self.assertEqual(ctx.exception.code,
                         "supplychain-delegation-signature-invalid")

    def test_unknown_keyid_ignored_not_counted(self):
        dwire = _deleg_wire(1, [_deleg("payments-team", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        awire = _seal("link", _authz("skills/payments/x"),
                      [("mallory", _M1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire, awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, EVAL)
        self.assertEqual(ctx.exception.code,
                         "supplychain-delegation-signature-invalid")

    def test_revocation_by_absence(self):
        dwire = _deleg_wire(3, [_deleg("payments-team", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        trusted = {"delegations_version": 2,
                   "delegations": {"old-team": 1}}
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire, awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, EVAL,
                                          trusted=trusted)
        self.assertEqual(ctx.exception.code, "supplychain-delegation-revoked")

    def test_rollback(self):
        dwire = _deleg_wire(2, [_deleg("payments-team", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(
                dwire, awire, "skills/payments/x", ROOT_TRUST, EVAL,
                trusted={"delegations_version": 3})
        self.assertEqual(ctx.exception.code, "supplychain-rollback")

    def test_expiry_boundary_exclusive(self):
        # expires == eval_start is frozen (TUF: expires <= eval_start).
        dwire = _deleg_wire(1, [_deleg("payments-team", ["pay-k1"], 1,
                                       ["skills/payments/*"])],
                             expires="2020-01-01T00:00:00Z")
        awire = _authz_wire("skills/payments/x", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire, awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, 1577836800.0)
        self.assertEqual(ctx.exception.code, "supplychain-frozen")

    def test_snapshot_binding(self):
        dwire, awire = self._ok()
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire, awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, EVAL,
                                          parent_pin="00" * 32)
        self.assertEqual(ctx.exception.code,
                         "supplychain-snapshot-mismatch")
        # correct pin passes
        rep = sc.verify_delegated_authority(
            dwire, awire, "skills/payments/x", ROOT_TRUST, EVAL,
            parent_pin=hashlib.sha256(dwire).hexdigest())
        self.assertTrue(rep["ok"])

    def test_eval_start_rejected(self):
        dwire, awire = self._ok()
        for bad in (-1.0, "now", float("nan"), float("inf"),
                    float("-inf"), True):
            with self.assertRaises(sc.SupplyChainError) as ctx:
                sc.verify_delegated_authority(dwire, awire,
                                              "skills/payments/x",
                                              ROOT_TRUST, bad)
            self.assertEqual(ctx.exception.code,
                             "supplychain-eval-start-invalid")

    def test_skill_mismatch_malformed(self):
        dwire = _deleg_wire(1, [_deleg("payments-team", ["pay-k1"], 1,
                                       ["skills/payments/*"])])
        awire = _authz_wire("skills/payments/other", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority(dwire, awire,
                                          "skills/payments/x",
                                          ROOT_TRUST, EVAL)
        self.assertEqual(ctx.exception.code, "supplychain-malformed")


class Lifecycle(unittest.TestCase):
    def test_legit(self):
        rep = sc.verify_lifecycle(_layout_wire(), _good_link_wires(),
                                  KEYS, EVAL)
        self.assertTrue(rep["ok"])
        self.assertEqual(len(rep["transitions"]), 3)
        ev = sc.to_evidence(rep)
        self.assertEqual(ev["evidence_digest"], rep["evidence_digest"])
        self.assertTrue(ev["record_digest"])

    def test_layout_smuggled_disallow_refused(self):
        doc = {"bundle": "b", "version": 1, "expires": FUTURE,
               "authority": {"keyids": ["r1"], "threshold": 1},
               "transitions": [
                   {"name": "t",
                    "signers": {"keyids": ["pay-k1"], "threshold": 1},
                    "expected_materials": [],
                    "expected_products": [["DISALLOW", "*"]]}]}
        wire = _seal("layout", doc, [("r1", _R1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_lifecycle(wire, [], KEYS, EVAL)
        self.assertEqual(ctx.exception.code, "supplychain-malformed")

    def test_transition_rules_exhaust_queue(self):
        # The module appends its own terminal DISALLOW: any leftover
        # file anywhere refuses.
        l0 = _link("publish", {}, {"bundle.tar.gz": _D["bundle.tar.gz"],
                                   "manifest.json": _D["manifest.json"],
                                   "extra.txt": _D["manifest.json"]},
                   "0" * 64)
        h0 = hashlib.sha256(tuf_canonical_json(l0)).hexdigest()
        l1 = _link("fetch", {"bundle.tar.gz": _D["bundle.tar.gz"],
                             "manifest.json": _D["manifest.json"]},
                   {"unpacked/skill.py": _D["unpacked/skill.py"]}, h0)
        h1 = hashlib.sha256(tuf_canonical_json(l1)).hexdigest()
        l2 = _link("install",
                   {"unpacked/skill.py": _D["unpacked/skill.py"]},
                   {"installed.marker": _D["installed.marker"]}, h1)
        wires = [_seal("link", l, [("pay-k1", _P1)])
                 for l in (l0, l1, l2)]
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_lifecycle(_layout_wire(), wires, KEYS, EVAL)
        self.assertEqual(ctx.exception.code,
                         "supplychain-transition-rules-failed")

    def test_to_evidence_round_link(self):
        dwire, awire = (_deleg_wire(1, [_deleg("t", ["pay-k1"], 1,
                                                ["skills/*"])]),
                        _authz_wire("skills/x", [("pay-k1", _P1)]))
        rep = sc.verify_delegated_authority(dwire, awire, "skills/x",
                                            ROOT_TRUST, EVAL)
        ev = sc.to_evidence(rep)
        self.assertEqual(ev["subject"], "skills/x")
        self.assertEqual(ev["verdict"], "authorized")
        self.assertEqual(ev["evidence_digest"], rep["evidence_digest"])
        self.assertEqual(len(ev["record_digest"]), 64)

    def test_to_evidence_missing_digest_refused(self):
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.to_evidence({"ok": True, "kind": "delegated-authority",
                            "skill": "skills/x"})
        self.assertEqual(ctx.exception.code, "supplychain-malformed")

    def test_non_bytes_wire_with_parent_pin_refused(self):
        dwire = _deleg_wire(1, [_deleg("t", ["pay-k1"], 1,
                                       ["skills/*"])])
        awire = _authz_wire("skills/x", [("pay-k1", _P1)])
        with self.assertRaises(sc.SupplyChainError) as ctx:
            sc.verify_delegated_authority("not-bytes", awire, "skills/x",
                                          ROOT_TRUST, EVAL,
                                          parent_pin="00" * 32)
        self.assertEqual(ctx.exception.code, "supplychain-malformed")


class Taxonomy(unittest.TestCase):
    def test_codes_registered(self):
        from gov import decision_codes
        tax = decision_codes.TAXONOMY
        self.assertEqual(len(tax), TAXONOMY_PIN)
        self.assertEqual(len(sc.CODES), 13)
        for code in sc.CODES:
            self.assertIn(code, tax, code)
            self.assertEqual(tax[code]["domain"], "supplychain")


if __name__ == "__main__":
    unittest.main()
