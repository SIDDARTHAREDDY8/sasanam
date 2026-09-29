#!/usr/bin/env python3
"""Wave-199 lane A: Tink-inspired keyset-lifecycle unit tests.

Covers the DISABLED-warn-and-rotate, DESTROYED-terminal,
material-free ``keyset_info()`` projection, primary-authorized
disable/destroy ceremonies, the KMS registry lifecycle vocabulary,
the envelope-rotation audit hook, and the provisioner mint-budget
envelope wiring. Deterministic seeds (SHA256 of test tags);
synthetic/local only.
"""

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from gov import ed25519 as _ed
from gov import keyset as ks
from gov.kms import (EnvelopeKeyRing, FakeKmsProvider, KeyDescription,
                     KmsError, rotate_envelope_keyring)
from gov.provisioner import (LifetimeClaims, Provisioner, ProvisionerType)


def _seed(tag):
    return hashlib.sha256(("wave199-unit:" + tag).encode()).digest()


def _v2():
    keyset, _s1 = ks.new_keyset(_seed("v1"))
    keyset, _s2 = ks.rotate_keyset(keyset, _seed("v2"), _seed("v1"))
    return keyset


def _material_strings(keyset):
    doc = keyset.to_dict()
    out = set()
    for v in doc["versions"]:
        out.add(v["public_key_hex"])
    for rec in doc.get("rotation_lineage", []):
        out.add(rec["to_public_key_hex"])
        out.add(rec["sig"])
    for rec in doc.get("revocations", []):
        out.add(rec["sig"])
    for rec in doc.get("status_changes", []):
        out.add(rec["sig"])
    return out


def _assert_material_free(testcase, projection, keyset):
    snap = json.dumps(projection, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str)
    for m in _material_strings(keyset):
        testcase.assertNotIn(m, snap,
                             "projection leaks key material")
    # No material-bearing field names anywhere in the projection.
    def walk(obj, path="$"):
        if isinstance(obj, dict):
            for k, v in obj.items():
                testcase.assertNotIn(
                    k, {"public_key_hex", "to_public_key_hex", "sig",
                        "wrapped_b64", "wrapped"},
                    "material field %s at %s" % (k, path))
                walk(v, "%s.%s" % (path, k))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                walk(v, "%s[%d]" % (path, i))
    walk(projection)


class DisableCeremony(unittest.TestCase):
    def setUp(self):
        ks._warned_disabled.clear()

    def test_disable_happy_path(self):
        keyset = _v2()
        keyset = ks.disable_version(keyset, 1, "winding down", _seed("v2"))
        self.assertEqual(keyset.version(1).status, ks.STATUS_DISABLED)
        self.assertEqual(keyset.version(2).status, ks.STATUS_ACTIVE)
        ok, err = keyset.verify()
        self.assertTrue(ok, err)
        self.assertEqual(len(keyset.to_dict()["status_changes"]), 1)

    def test_disable_wrong_primary_seed_refused(self):
        with self.assertRaises(ks.KeysetError):
            ks.disable_version(_v2(), 1, "x", _seed("wrong"))

    def test_disable_primary_refused(self):
        with self.assertRaises(ks.KeysetError):
            ks.disable_version(_v2(), 2, "x", _seed("v2"))

    def test_disable_twice_refused(self):
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        with self.assertRaises(ks.KeysetError):
            ks.disable_version(keyset, 1, "again", _seed("v2"))

    def test_disable_from_revoked_refused(self):
        # A revoked (compromised) key must never be downgraded to
        # warn-and-verify: the compromised path is revoked -> destroyed.
        keyset = ks.revoke_version(_v2(), 1, "compromised", _seed("v2"))
        with self.assertRaises(ks.KeysetError):
            ks.disable_version(keyset, 1, "winding down", _seed("v2"))

    def test_disable_empty_reason_refused(self):
        with self.assertRaises(ks.KeysetError):
            ks.disable_version(_v2(), 1, "  ", _seed("v2"))


class DisabledVerifyWarn(unittest.TestCase):
    def setUp(self):
        ks._warned_disabled.clear()

    def _disabled(self):
        return ks.disable_version(_v2(), 1, "winding down", _seed("v2"))

    def _entry(self):
        kid = ks.ed25519_key_id(_ed.publickey(_seed("v1")))
        return {"sig_key_id": kid, "sig_key_version": 1}

    def test_disabled_verifies_with_loud_warning(self):
        keyset = self._disabled()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            found, reason = keyset.find_verifying_key(self._entry())
        self.assertIsNotNone(found)
        self.assertIn("DISABLED", reason)
        self.assertIn("GOVERNANCE WARNING", buf.getvalue())
        self.assertIn("DISABLED", buf.getvalue())

    def test_disabled_warning_deduped_per_process(self):
        keyset = self._disabled()
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            keyset.find_verifying_key(self._entry())
            keyset.find_verifying_key(self._entry())
        self.assertEqual(buf.getvalue().count("GOVERNANCE WARNING"), 1)
        # ... but the reason still says DISABLED every time (the audit
        # path records it regardless of the stderr dedup).
        _, reason = keyset.find_verifying_key(self._entry())
        self.assertIn("DISABLED", reason)

    def test_disabled_never_mints(self):
        keyset = self._disabled()
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_for_version(keyset, 1, _seed("v1"))

    def test_disabled_legacy_path_warns(self):
        keyset = self._disabled()
        kid = ks.ed25519_key_id(_ed.publickey(_seed("v1")))
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            found, reason = keyset.find_verifying_key({"sig_key_id": kid})
        self.assertIsNotNone(found)
        self.assertIn("DISABLED", reason)
        self.assertIn("GOVERNANCE WARNING", buf.getvalue())


class DestroyCeremony(unittest.TestCase):
    def test_destroy_happy_path(self):
        keyset = ks.destroy_version(_v2(), 1, "compromised", _seed("v2"))
        self.assertEqual(keyset.version(1).status, ks.STATUS_DESTROYED)
        ok, err = keyset.verify()
        self.assertTrue(ok, err)

    def test_destroy_refused_everywhere(self):
        keyset = ks.destroy_version(_v2(), 1, "compromised", _seed("v2"))
        kid = ks.ed25519_key_id(_ed.publickey(_seed("v1")))
        entry = {"sig_key_id": kid, "sig_key_version": 1}
        found, reason = keyset.find_verifying_key(entry)
        self.assertIsNone(found)
        self.assertIn("destroyed", reason)
        found_f, reason_f = keyset.find_verifying_key_for_forensics(entry)
        self.assertIsNone(found_f)
        self.assertIn("destroyed", reason_f)
        # Legacy (unversioned) path too.
        found_l, _ = keyset.find_verifying_key({"sig_key_id": kid})
        self.assertIsNone(found_l)
        with self.assertRaises(ks.KeysetError):
            ks.keyset_signer_for_version(keyset, 1, _seed("v1"))

    def test_destroy_primary_refused(self):
        with self.assertRaises(ks.KeysetError):
            ks.destroy_version(_v2(), 2, "x", _seed("v2"))

    def test_destroy_twice_refused(self):
        keyset = ks.destroy_version(_v2(), 1, "compromised", _seed("v2"))
        with self.assertRaises(ks.KeysetError):
            ks.destroy_version(keyset, 1, "again", _seed("v2"))

    def test_destroy_from_disabled_allowed(self):
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        keyset = ks.destroy_version(keyset, 1, "compromised", _seed("v2"))
        self.assertEqual(keyset.version(1).status, ks.STATUS_DESTROYED)
        ok, err = keyset.verify()
        self.assertTrue(ok, err)

    def test_revoke_then_destroy_chain_verifies(self):
        # A revoked version can be destroyed afterwards; the revocation
        # record stays valid against the destroyed final status.
        keyset = ks.revoke_version(_v2(), 1, "compromised", _seed("v2"))
        keyset = ks.destroy_version(keyset, 1, "purged", _seed("v2"))
        ok, err = keyset.verify()
        self.assertTrue(ok, err)
        found, _ = keyset.find_verifying_key_for_forensics(
            {"sig_key_id": ks.ed25519_key_id(_ed.publickey(_seed("v1"))),
             "sig_key_version": 1})
        self.assertIsNone(found)


class StatusChangeAuthorization(unittest.TestCase):
    def test_tampered_reason_breaks_chain(self):
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        doc = keyset.to_dict()
        doc["status_changes"][0]["reason"] = "tampered"
        bad = ks.Keyset.from_dict(doc)
        ok, err = bad.verify()
        self.assertFalse(ok)
        self.assertIn("status-change", err)

    def test_tampered_to_status_breaks_chain(self):
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        doc = keyset.to_dict()
        doc["status_changes"][0]["to_status"] = "active"
        doc["versions"][0]["status"] = "active"
        try:
            bad = ks.Keyset.from_dict(doc)
        except ks.KeysetError:
            return  # fail-closed at parse (two active primaries)
        ok, _err = bad.verify()
        self.assertFalse(ok)  # sig covers to_status; also primary rule

    def test_chain_break_between_records_detected(self):
        # Two records with individually valid signatures but a broken
        # from/to chain: the second claims from_status "revoked" while
        # the first ended at "disabled".
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        kv1 = keyset.version(1)
        pv, pkv = keyset.primary_version, keyset.version(2)
        kh = keyset.keyset_hash()
        body = (ks.STATUS_CHANGE_DOMAIN + ks.status_change_statement(
            1, kv1.key_id, "revoked", ks.STATUS_DESTROYED, "purge",
            pv, pkv.key_id, kh, at=1234567890))
        rec = {"version": 1, "key_id": kv1.key_id,
               "from_status": "revoked", "to_status": ks.STATUS_DESTROYED,
               "reason": "purge", "at": 1234567890,
               "changed_by_version": pv, "changed_by_key_id": pkv.key_id,
               "keyset_hash": kh,
               "sig": _ed.sign(_seed("v2"), body).hex()}
        doc = keyset.to_dict()
        doc["status_changes"].append(rec)
        doc["versions"][0]["status"] = ks.STATUS_DESTROYED
        bad = ks.Keyset.from_dict(doc)
        ok, err = bad.verify()
        self.assertFalse(ok)
        self.assertIn("chain break", err)

    def test_history_survives_authorizer_destruction(self):
        # The authorizing key's LATER death must not invalidate the
        # records it signed while live: v2 (primary) disables v1, then
        # v2 is rotated out and destroyed. The disable record (signed
        # by v2) and the rotation record (signed by v1) must still
        # verify -- otherwise destroying retired keys would brick the
        # keyset.
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        keyset, _ = ks.rotate_keyset(keyset, _seed("v3"), _seed("v2"))
        keyset = ks.destroy_version(keyset, 2, "purged", _seed("v3"))
        ok, err = keyset.verify()
        self.assertTrue(ok, err)
        self.assertEqual(keyset.version(1).status, ks.STATUS_DISABLED)
        self.assertEqual(keyset.version(2).status, ks.STATUS_DESTROYED)
        self.assertEqual(keyset.version(3).status, ks.STATUS_ACTIVE)

    def test_revoking_revoker_does_not_unban(self):
        # v2 revokes compromised v1; v2 is later compromised and revoked
        # by v3. v1's revocation record (signed by v2) must still hold --
        # revoking the revoker must not un-ban v1, nor brick the keyset.
        keyset = ks.revoke_version(_v2(), 1, "compromised", _seed("v2"))
        keyset, _ = ks.rotate_keyset(keyset, _seed("v3"), _seed("v2"))
        keyset = ks.revoke_version(keyset, 2, "compromised", _seed("v3"))
        ok, err = keyset.verify()
        self.assertTrue(ok, err)
        entry = {"sig_key_id": ks.ed25519_key_id(_ed.publickey(_seed("v1"))),
                 "sig_key_version": 1}
        found, _ = keyset.find_verifying_key(entry)
        self.assertIsNone(found)  # v1 stays refused on the standard path

    def test_primary_status_change_record_refused(self):
        keyset = _v2()
        pv, pkv = keyset.primary_version, keyset.version(2)
        kh = keyset.keyset_hash()
        body = (ks.STATUS_CHANGE_DOMAIN + ks.status_change_statement(
            2, pkv.key_id, "active", ks.STATUS_DISABLED, "x",
            1, keyset.version(1).key_id, kh, at=1234567890))
        rec = {"version": 2, "key_id": pkv.key_id,
               "from_status": "active", "to_status": ks.STATUS_DISABLED,
               "reason": "x", "at": 1234567890,
               "changed_by_version": 1,
               "changed_by_key_id": keyset.version(1).key_id,
               "keyset_hash": kh,
               "sig": _ed.sign(_seed("v1"), body).hex()}
        doc = keyset.to_dict()
        doc["status_changes"].append(rec)
        bad = ks.Keyset.from_dict(doc)
        ok, err = bad.verify()
        self.assertFalse(ok)
        self.assertIn("primary", err)


class KeysetInfoProjection(unittest.TestCase):
    def test_info_is_material_free(self):
        keyset = _v2()
        info = keyset.keyset_info()
        _assert_material_free(self, info, keyset)
        self.assertEqual(info["format"], ks.KEYSET_INFO_FORMAT)
        self.assertEqual(info["primary_version"], 2)
        by_ver = {v["version"]: v for v in info["versions"]}
        self.assertEqual(by_ver[1]["status"], "verify-only")
        self.assertEqual(by_ver[2]["status"], "active")
        self.assertEqual(by_ver[2]["key_id"], info["primary_key_id"])
        self.assertEqual(info["keyset_hash"], keyset.keyset_hash())
        self.assertEqual(info["rotation_count"], 1)

    def test_info_reflects_lifecycle(self):
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        keyset, _ = ks.rotate_keyset(keyset, _seed("v3"), _seed("v2"))
        keyset = ks.destroy_version(keyset, 2, "compromised", _seed("v3"))
        info = keyset.keyset_info()
        _assert_material_free(self, info, keyset)
        by_ver = {v["version"]: v for v in info["versions"]}
        self.assertEqual(by_ver[1]["status"], "disabled")
        self.assertEqual(by_ver[2]["status"], "destroyed")
        self.assertEqual(by_ver[3]["status"], "active")
        self.assertEqual(info["status_change_count"], 2)

    def test_adversary_with_snapshot_learns_no_material(self):
        # The threat model: the adversary holds the whole snapshot.
        # Every key-material string in the full document must be absent.
        keyset = ks.destroy_version(_v2(), 1, "compromised", _seed("v2"))
        snap = json.dumps(keyset.keyset_info(), sort_keys=True)
        for m in _material_strings(keyset):
            self.assertNotIn(m, snap)


class StatusChangedEvent(unittest.TestCase):
    def test_event_shape_and_material_free(self):
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        # from_status is derived from the signed status-change chain,
        # not caller-supplied: the event cannot misstate the prior status.
        evt = ks.keyset_status_changed_event(keyset, 1, "winding down")
        self.assertEqual(evt["event"], "keyset_status_changed")
        self.assertEqual(evt["transition"]["version"], 1)
        self.assertEqual(evt["transition"]["from_status"], "verify-only")
        self.assertEqual(evt["transition"]["to_status"], "disabled")
        self.assertEqual(evt["transition"]["reason"], "winding down")
        _assert_material_free(self, evt, keyset)

    def test_event_derives_from_status_from_signed_chain(self):
        # A caller cannot talk the event into a different from_status:
        # the signed chain is the authority.
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        evt = ks.keyset_status_changed_event(keyset, 1, "winding down")
        rec = keyset.latest_status_change(1)
        self.assertIsNotNone(rec)
        self.assertEqual(evt["transition"]["from_status"],
                         rec["from_status"])

    def test_event_rejects_bad_inputs(self):
        keyset = _v2()
        # No recorded status change for version 1: fail closed rather
        # than describing a transition that never happened.
        with self.assertRaises(ks.KeysetError):
            ks.keyset_status_changed_event(keyset, 1, "x")
        with self.assertRaises(ks.KeysetError):
            ks.keyset_status_changed_event(keyset, 1, " ")
        with self.assertRaises(ks.KeysetError):
            ks.keyset_status_changed_event(keyset, 99, "x")


class KmsLifecycle(unittest.TestCase):
    def test_destroy_refuses_everything(self):
        prov = FakeKmsProvider(["k1"])
        prov.destroy_key("k1")
        with self.assertRaises(KmsError):
            prov.wrap_data_key("k1", b"x" * 32)
        with self.assertRaises(KmsError):
            prov.unwrap_data_key("k1", b"junk")
        with self.assertRaises(KmsError):
            prov.describe_key("k1")

    def test_status_vocabulary_on_describe(self):
        prov = FakeKmsProvider(["k1", "k2"])
        self.assertEqual(prov.describe_key("k1").describe()["status"],
                         "enabled")
        prov.disable_key("k2")
        d2 = prov.describe_key("k2").describe()
        self.assertEqual(d2["status"], "disabled")
        self.assertFalse(d2["enabled"])

    def test_status_vocabulary_is_enforced(self):
        # A typo'd status must fail closed at construction, never flow
        # silently into describe() dicts or the rotation audit event.
        with self.assertRaises(ValueError):
            KeyDescription("k1", "fake", status="disbled")
        # Omitted status still derives from the legacy enabled boolean.
        self.assertEqual(KeyDescription("k1", "fake").status, "enabled")
        self.assertEqual(KeyDescription("k1", "fake",
                                        enabled=False).status, "disabled")

    def test_disabled_semantics_unchanged(self):
        # The adjacent suite pins this; the lifecycle change must not
        # move it: disabled still refuses wrap/unwrap but describes.
        prov = FakeKmsProvider(["k1"])
        prov.disable_key("k1")
        with self.assertRaises(KmsError):
            prov.wrap_data_key("k1", b"x" * 32)
        self.assertEqual(prov.describe_key("k1").describe()["status"],
                         "disabled")


class EnvelopeRotationAuditHook(unittest.TestCase):
    def test_rotation_emits_material_free_event(self):
        prov = FakeKmsProvider(["k1"])
        with tempfile.TemporaryDirectory(prefix="govksl-") as tmp:
            path = str(Path(tmp) / "ring.json")
            EnvelopeKeyRing.generate(prov, "k1").save(path)
            events = []
            ring, new_epoch = rotate_envelope_keyring(
                path, prov, lifecycle_audit=events.append)
            self.assertEqual(len(events), 1)
            evt = events[0]
            self.assertEqual(evt["event"], "key_rotation")
            self.assertEqual(evt["new_epoch"], new_epoch)
            self.assertEqual(evt["active_epoch"], new_epoch)
            statuses = {e["epoch"]: e["status"] for e in evt["epochs"]}
            self.assertEqual(statuses[new_epoch], "active")
            # Material-free: no wrapped blobs, no key bytes.
            snap = json.dumps(evt, sort_keys=True, default=str)
            self.assertNotIn("wrapped_b64", snap)
            for _ep, wd in ring._wrapped.items():
                self.assertNotIn(wd.wrapped_blob.hex(), snap)
            self.assertEqual(evt["wrapping_key"]["status"], "enabled")

    def test_hook_failure_does_not_fail_rotation(self):
        prov = FakeKmsProvider(["k1"])
        with tempfile.TemporaryDirectory(prefix="govksl-") as tmp:
            path = str(Path(tmp) / "ring.json")
            EnvelopeKeyRing.generate(prov, "k1").save(path)

            def bad_hook(_evt):
                raise RuntimeError("audit sink down")

            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                _ring, new_epoch = rotate_envelope_keyring(
                    path, prov, lifecycle_audit=bad_hook)
            self.assertTrue(new_epoch)
            self.assertIn("GOVERNANCE WARNING", buf.getvalue())

    def test_no_hook_no_event_no_behavior_change(self):
        prov = FakeKmsProvider(["k1"])
        with tempfile.TemporaryDirectory(prefix="govksl-") as tmp:
            path = str(Path(tmp) / "ring.json")
            EnvelopeKeyRing.generate(prov, "k1").save(path)
            ring, new_epoch = rotate_envelope_keyring(path, prov)
            self.assertTrue(new_epoch)
            self.assertEqual(ring._active_epoch, new_epoch)


class ProvisionerKeysetWiring(unittest.TestCase):
    def _claims(self):
        return LifetimeClaims(
            max_ttl_seconds=3600,
            allowed_scopes=frozenset({"tools:read"}),
            allowed_roles=frozenset({"operator"}),
            max_mints_per_run=5,
            revocation="keyset")

    def test_keyset_projection_on_provisioner(self):
        keyset = _v2()
        p = Provisioner("jwk-1", ProvisionerType.JWK, self._claims(),
                        keyset=keyset)
        proj = p.keyset_info_projection()
        self.assertIsNotNone(proj)
        _assert_material_free(self, proj, keyset)
        self.assertEqual(proj["primary_version"], 2)

    def test_no_keyset_no_projection(self):
        p = Provisioner("op-1", ProvisionerType.OPERATOR, self._claims())
        self.assertIsNone(p.keyset_info_projection())

    def test_bad_keyset_rejected(self):
        with self.assertRaises(TypeError):
            Provisioner("jwk-x", ProvisionerType.JWK, self._claims(),
                        keyset=object())

    def test_mint_event_carries_projection(self):
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        from gov.provisioner import ProvisionerRegistry
        policy_text = ("version: 2\nroles:\n  operator: [read_file]\n"
                       "policies:\n  - id: allow-all\n    effect: allow\n"
                       "    match:\n      tool: [read_file]\n"
                       "    reason: keyset lifecycle fixture\n")
        run_dir = Path(tempfile.mkdtemp(prefix="govkslmint-"))
        (run_dir / "policy.yaml").write_text(policy_text)
        policy = PolicyEngine(str(run_dir / "policy.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        keyset = ks.disable_version(_v2(), 1, "winding down", _seed("v2"))
        registry = ProvisionerRegistry([
            Provisioner("jwk-1", ProvisionerType.JWK, self._claims(),
                        keyset=keyset),
        ])
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack="keyset lifecycle test: synthetic executor",
            provisioner_registry=registry)
        ex.mint_identity("agent:org1:run-7", "operator", "org1",
                         provisioner="jwk-1", ttl_seconds=600,
                         scopes=["tools:read"])
        minted = []
        with open(run_dir / "actions.jsonl", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    e = json.loads(line)
                    if e.get("event") == "identity_minted":
                        minted.append(e)
        self.assertEqual(len(minted), 1)
        e = minted[0]
        self.assertEqual(e["revocation"], "keyset")
        self.assertEqual(e["policy"]["max_mints_per_run"], 5)
        self.assertIn("keyset", e)
        _assert_material_free(self, e["keyset"], keyset)
        by_ver = {v["version"]: v
                  for v in e["keyset"]["versions"]}
        self.assertEqual(by_ver[1]["status"], "disabled")

    def test_mint_event_without_keyset_is_byte_identical(self):
        # No keyset attached -> no "keyset" field at all (the wave-192
        # packet-section byte-identical guarantee).
        from gov.executor import ToolExecutor
        from gov.policy import PolicyEngine
        from gov.log import ActionLog
        from gov.approvals import ApprovalQueue
        from gov.provisioner import ProvisionerRegistry
        policy_text = ("version: 2\nroles:\n  operator: [read_file]\n"
                       "policies:\n  - id: allow-all\n    effect: allow\n"
                       "    match:\n      tool: [read_file]\n"
                       "    reason: keyset lifecycle fixture\n")
        run_dir = Path(tempfile.mkdtemp(prefix="govkslmint-"))
        (run_dir / "policy.yaml").write_text(policy_text)
        policy = PolicyEngine(str(run_dir / "policy.yaml"))
        log = ActionLog(run_dir / "actions.jsonl")
        approvals = ApprovalQueue(run_dir, log)
        registry = ProvisionerRegistry([
            Provisioner("jwk-1", ProvisionerType.JWK, self._claims()),
        ])
        ex = ToolExecutor(
            run_dir, policy, log, approvals,
            ledger_path=run_dir / "egress_ledger.jsonl",
            ungoverned_ack="keyset lifecycle test: synthetic executor",
            provisioner_registry=registry)
        ex.mint_identity("agent:org1:run-7", "operator", "org1",
                         provisioner="jwk-1", ttl_seconds=600,
                         scopes=["tools:read"])
        with open(run_dir / "actions.jsonl", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    e = json.loads(line)
                    if e.get("event") == "identity_minted":
                        self.assertNotIn("keyset", e)


if __name__ == "__main__":
    unittest.main()
