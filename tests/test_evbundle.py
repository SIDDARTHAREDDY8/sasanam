#!/usr/bin/env python3
"""Unit tests for evidence bundle v2 + Rekor contract
(gov/evidence_bundle_v2.py) and the 8 ``evbundle-*`` decision codes.

Conventions: staging default; fixtures through the audited
evidence-cert ceremony (fixed seeds, independent literals); the
refusal lattice asserts each code at its exact trigger point;
``verify`` results asserted with ``is True`` (wave-243); the
lane-local taxonomy pin is asserted on raw source literals, never
``len(dict)`` (wave-260); ``tests/test_decision_codes.py`` keeps the
pre-lane global pin at 1325 for the merge coordinator.
"""

import base64
import hashlib
import json
import os
import re
import secrets
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")
# Audit-log HMAC chain key: tests/__init__ provisions one on package
# import; setdefault covers direct-script runs.
os.environ.setdefault("GOV_LOG_KEY", secrets.token_hex(32))
os.environ.setdefault("GOV_LOG_KEY_EPOCH", "w270-evbundle-ut")

from gov import ed25519 as ed  # noqa: E402
from gov import evidence_certs as ec  # noqa: E402
from gov import evidence_bundle_v2 as eb2  # noqa: E402
from gov import kms as kms_mod  # noqa: E402
from gov.decision_codes import TAXONOMY  # noqa: E402

NOW = 1790860000
POP_DOMAIN = b"evcert-pop-v1"  # spec-pinned, not from the module
ARC = "1.3.6.1.4.1.99999"
APPROVAL = "a" * 32
INTENT = "d" * 64
ISSUER = "https://issuer.example.com"

EXPECTED_EVBUNDLE_CODES = [
    ("evbundle-malformed", "medium"),
    ("evbundle-unauthorized-producer", "high"),
    ("evbundle-join-mismatch", "high"),
    ("evbundle-issuance-unverifiable", "high"),
    ("evbundle-inclusion-unverified", "medium"),
    ("evbundle-checkpoint-invalid", "medium"),
    ("evbundle-consistency-invalid", "medium"),
    ("evbundle-transparency-unavailable", "medium"),
]


def _keypair(byte):
    seed = bytes([byte & 0xFF]) * 32
    return seed, ed.publickey(seed)


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


class V2Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="evbundle-ut-")
        self.audit_path = os.path.join(self.tmp, "audit.jsonl")

    def make_ca(self, **over):
        self.fake = kms_mod.FakeKmsProvider(["ca-key-1"])
        approvals = {APPROVAL: {"decider": "alice", "state": "pending"}}
        kw = dict(kms_provider=over.pop("kms_provider", self.fake),
                  ca_key_id="ca-key-1",
                  ca_public_key=self.fake.test_signing_public_key(
                      "ca-key-1"),
                  issuers=[ISSUER],
                  approval_lookup=approvals.get,
                  audit_log_path=over.pop("audit_log_path",
                                          self.audit_path),
                  anchor_reachable=lambda: True,
                  oid_arc=ARC,
                  now=lambda: NOW)
        kw.update(over)
        return ec.EvidenceCA(**kw)

    def issue_cert(self, ca, seed_byte=0x01, approval_id=APPROVAL):
        seed, pub = _keypair(seed_byte)
        chal = (POP_DOMAIN + approval_id.encode("utf-8")
                + hashlib.sha256(pub).digest())
        req = {"identity_assertion": {"iss": ISSUER, "sub": "alice",
                                      "exp": NOW + 3600},
               "ephemeral_pub": pub,
               "pop_sig": ed.sign(seed, chal),
               "approval_id": approval_id,
               "intent_digest": INTENT}
        cert, _entry = ca.issue(**req)
        return cert, seed, pub

    def harness(self, seed_byte=0x01):
        ca = self.make_ca()
        cert, seed, pub = self.issue_cert(ca, seed_byte=seed_byte)
        ca_pub = self.fake.test_signing_public_key("ca-key-1")
        return ca, cert, seed, pub, ca_pub

    def make_log(self, **kw):
        kw.setdefault("producer_auth_verifier",
                      eb2.default_producer_auth_verifier)
        kw.setdefault("now", lambda: NOW)
        return eb2.make_log(**kw)

    def seal_kwargs(self, cert, seed, ca_pub, body=None,
                    approval_id=APPROVAL, intent_digest=INTENT):
        body = {"decision": "deny"} if body is None else body
        sig = ed.sign(seed, _canonical(body))
        return dict(artifact_body=body, cert=cert,
                    artifact_signature=bytes(sig),
                    approval_id=approval_id, intent_digest=intent_digest,
                    ca_public_key=bytes(ca_pub), verify_time=NOW)

    def assertCode(self, code, fn, *args, **kwargs):
        with self.assertRaises(eb2.EvidenceBundleV2Error) as ctx:
            fn(*args, **kwargs)
        self.assertEqual(ctx.exception.code, code)
        return ctx.exception


class SealTests(V2Base):
    def test_seal_and_verify_round_trip(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        sealed = eb2.seal_evidence(**self.seal_kwargs(cert, seed, ca_pub))
        self.assertEqual(sealed["kind"], "evidence-bundle.v2")
        out = eb2.verify_sealed_bundle(sealed=sealed,
                                       audit_log_path=self.audit_path,
                                       ca_public_key=bytes(ca_pub),
                                       verify_time=NOW)
        self.assertIs(out["verified"], True)
        self.assertEqual(out["cert_digest"], sealed["cert_digest"])
        self.assertIn("does NOT prove", out["honest_claims"])

    def test_seal_forged_signature_raises_evcert(self):
        _ca, cert, _seed, _pub, ca_pub = self.harness()
        other_seed, _other_pub = _keypair(0xEE)
        kw = self.seal_kwargs(cert, other_seed, ca_pub)
        with self.assertRaises(ec.EvidenceCertError) as ctx:
            eb2.seal_evidence(**kw)
        self.assertEqual(ctx.exception.code, "evcert-binding-invalid")

    def test_seal_approval_mismatch_raises_evcert(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        kw = self.seal_kwargs(cert, seed, ca_pub,
                              approval_id="b" * 32)
        with self.assertRaises(ec.EvidenceCertError) as ctx:
            eb2.seal_evidence(**kw)
        self.assertEqual(ctx.exception.code, "evcert-binding-invalid")

    def test_malformed_non_dict_body(self):
        self.assertCode("evbundle-malformed", eb2.build_artifact, "nope")

    def test_malformed_short_signature(self):
        _ca, cert, _seed, _pub, ca_pub = self.harness()
        kw = self.seal_kwargs(cert, _seed, ca_pub)
        kw["artifact_signature"] = b"short"
        self.assertCode("evbundle-malformed", eb2.seal_evidence, **kw)

    def test_join_mismatch_swapped_cert_digest(self):
        ca, cert, seed, _pub, ca_pub = self.harness()
        sealed = eb2.seal_evidence(**self.seal_kwargs(cert, seed, ca_pub))
        cert2, _, _ = self.issue_cert(ca, seed_byte=0x02)
        sealed = dict(sealed)
        sealed["cert_digest"] = ec.cert_digest(cert2)
        self.assertCode("evbundle-join-mismatch",
                       eb2.verify_sealed_bundle, sealed=sealed,
                       audit_log_path=self.audit_path,
                       ca_public_key=bytes(ca_pub), verify_time=NOW)

    def test_join_mismatch_swapped_artifact_digest(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        sealed = eb2.seal_evidence(**self.seal_kwargs(cert, seed, ca_pub))
        sealed = dict(sealed)
        sealed["signature_attestation"] = dict(
            sealed["signature_attestation"])
        sealed["signature_attestation"]["artifact_digest"] = "00" * 32
        self.assertCode("evbundle-join-mismatch",
                       eb2.verify_sealed_bundle, sealed=sealed,
                       audit_log_path=self.audit_path,
                       ca_public_key=bytes(ca_pub), verify_time=NOW)

    def test_verify_re_runs_ceremony_on_sealed_cert(self):
        # A swapped attestation signature must refuse with evcert-*,
        # not verify on joins alone.
        _ca, cert, seed, _pub, ca_pub = self.harness()
        sealed = eb2.seal_evidence(**self.seal_kwargs(cert, seed, ca_pub))
        sealed["signature_attestation"]["signature"] =\
            base64.b64encode(b"\x00" * 64).decode("ascii")
        with self.assertRaises(ec.EvidenceCertError) as ctx:
            eb2.verify_sealed_bundle(sealed=sealed,
                                     audit_log_path=self.audit_path,
                                     ca_public_key=bytes(ca_pub),
                                     verify_time=NOW)
        self.assertTrue(ctx.exception.code.startswith("evcert-"))

    def test_issuance_absent_refused(self):
        ca, cert, seed, _pub, ca_pub = self.harness()
        # Issue through a different audit log so the join target is
        # absent from the bundle's log.
        other_path = os.path.join(self.tmp, "other.jsonl")
        ca2 = self.make_ca(audit_log_path=other_path)
        cert2, seed2, _ = self.issue_cert(ca2, seed_byte=0x03)
        sealed = eb2.seal_evidence(
            **self.seal_kwargs(cert2, seed2, ca_pub))
        self.assertCode("evbundle-issuance-unverifiable",
                       eb2.verify_sealed_bundle, sealed=sealed,
                       audit_log_path=self.audit_path,
                       ca_public_key=bytes(ca_pub), verify_time=NOW)

    def test_issuance_broken_chain_refused(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        sealed = eb2.seal_evidence(**self.seal_kwargs(cert, seed, ca_pub))
        with open(self.audit_path, "a", encoding="utf-8") as f:
            f.write('{"kind": "tampered"}\n')
        self.assertCode("evbundle-issuance-unverifiable",
                       eb2.verify_sealed_bundle, sealed=sealed,
                       audit_log_path=self.audit_path,
                       ca_public_key=bytes(ca_pub), verify_time=NOW)


class TransparencyTests(V2Base):
    def _submit(self, body=None):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        log = self.make_log()
        sub = eb2.submit_evidence(
            **self.seal_kwargs(cert, seed, ca_pub, body=body),
            audit_log_path=self.audit_path, transparency_log=log)
        return sub, log, cert, seed, ca_pub

    def test_submit_round_trip(self):
        sub, log, _cert, _seed, ca_pub = self._submit()
        receipt = sub["transparency_receipt"]
        self.assertIn("inclusion_proof", receipt)
        out = eb2.verify_submission(submission=sub,
                                    audit_log_path=self.audit_path,
                                    ca_public_key=bytes(ca_pub),
                                    verify_time=NOW,
                                    transparency_log=log)
        self.assertIs(out["verified"], True)
        self.assertIn("does NOT prove", out["honest_claims"])

    def test_submit_is_idempotent(self):
        sub1, log, cert, seed, ca_pub = self._submit(
            body={"decision": "deny"})
        sub2 = eb2.submit_evidence(
            **self.seal_kwargs(cert, seed, ca_pub,
                               body={"decision": "deny"}),
            audit_log_path=self.audit_path, transparency_log=log)
        r1, r2 = (sub1["transparency_receipt"],
                  sub2["transparency_receipt"])
        self.assertEqual(r1["inclusion_proof"]["leaf_index"],
                         r2["inclusion_proof"]["leaf_index"])
        self.assertEqual(r1["tree_size"], r2["tree_size"])
        self.assertEqual(r1["root"], r2["root"])

    def test_determinism_per_input(self):
        # Two submits append two leaves; per-input digests are stable.
        # (Ephemeral cert keys are single-use, so the two submits use
        # distinct seeds -- determinism is per artifact input.)
        _ca, cert1, seed1, _p1, ca_pub = self.harness(seed_byte=0x01)
        _ca2, cert2, seed2, _p2, _ca_pub2 = self.harness(seed_byte=0x02)
        sub1 = eb2.submit_evidence(
            **self.seal_kwargs(cert1, seed1, ca_pub, body={"x": 1}),
            audit_log_path=self.audit_path,
            transparency_log=self.make_log())
        sub2 = eb2.submit_evidence(
            **self.seal_kwargs(cert2, seed2, ca_pub, body={"x": 1}),
            audit_log_path=self.audit_path,
            transparency_log=self.make_log())
        d1 = sub1["sealed"]["artifact"]["artifact_digest"]
        d2 = sub2["sealed"]["artifact"]["artifact_digest"]
        self.assertEqual(d1, d2)
        self.assertEqual(d1, hashlib.sha256(
            _canonical({"x": 1})).hexdigest())

    def test_verify_contract_exact_bool(self):
        # Wave-243: pin the bool contract, not just truthiness.
        _ca, cert, seed, _pub, ca_pub = self.harness()
        log = self.make_log()
        subs = []
        for body in ({"x": 1}, {"other": 2}):
            subs.append(eb2.submit_evidence(
                **self.seal_kwargs(cert, seed, ca_pub, body=body),
                audit_log_path=self.audit_path, transparency_log=log))
        receipt = subs[0]["transparency_receipt"]
        checkpoint = {"log_id": receipt["log_id"],
                      "tree_size": receipt["tree_size"],
                      "root": receipt["root"],
                      "integrated_time": receipt["integrated_time"]}
        self.assertIs(log.verify_inclusion(
            subs[0]["sealed"]["artifact"]["artifact_digest"],
            receipt["inclusion_proof"], checkpoint), True)
        self.assertIs(log.verify_checkpoint(checkpoint), True)
        r2 = subs[1]["transparency_receipt"]
        checkpoint2 = {"log_id": r2["log_id"], "tree_size": r2["tree_size"],
                       "root": r2["root"],
                       "integrated_time": r2["integrated_time"]}
        self.assertIs(log.verify_consistency(checkpoint, checkpoint2),
                      True)

    def test_unauthorized_producer_bare_digest(self):
        log = self.make_log()
        self.assertCode("evbundle-unauthorized-producer", log.submit,
                       "ab" * 32, producer_auth=None)

    def test_unauthorized_producer_no_verifier_configured(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        log = eb2.make_log()  # no verifier: fail closed
        auth = {"kind": "evidence-cert", "cert": cert,
                "artifact_bytes": _canonical({"x": 1}),
                "artifact_signature": bytes(
                    ed.sign(seed, _canonical({"x": 1}))),
                "approval_id": APPROVAL, "intent_digest": INTENT,
                "ca_public_key": bytes(ca_pub), "verify_time": NOW}
        self.assertCode("evbundle-unauthorized-producer", log.submit,
                       "ab" * 32, producer_auth=auth)

    def test_unauthorized_producer_forged_signature(self):
        _ca, cert, _seed, _pub, ca_pub = self.harness()
        log = self.make_log()
        other_seed, _other_pub = _keypair(0xEE)
        digest = hashlib.sha256(_canonical({"x": 1})).hexdigest()
        auth = {"kind": "evidence-cert", "cert": cert,
                "artifact_bytes": _canonical({"x": 1}),
                "artifact_signature": bytes(
                    ed.sign(other_seed, _canonical({"x": 1}))),
                "approval_id": APPROVAL, "intent_digest": INTENT,
                "ca_public_key": bytes(ca_pub), "verify_time": NOW}
        self.assertCode("evbundle-unauthorized-producer", log.submit,
                       digest, producer_auth=auth)

    def test_unauthorized_producer_approval_mismatch(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        log = self.make_log()
        body = {"x": 1}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        auth = {"kind": "evidence-cert", "cert": cert,
                "artifact_bytes": _canonical(body),
                "artifact_signature": bytes(
                    ed.sign(seed, _canonical(body))),
                "approval_id": "b" * 32, "intent_digest": INTENT,
                "ca_public_key": bytes(ca_pub), "verify_time": NOW}
        self.assertCode("evbundle-unauthorized-producer", log.submit,
                       digest, producer_auth=auth)

    def test_unauthorized_producer_unknown_kind(self):
        log = self.make_log()
        self.assertCode("evbundle-unauthorized-producer", log.submit,
                       "ab" * 32, producer_auth={"kind": "mystery"})

    def test_unauthorized_producer_digest_mismatch(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()
        log = self.make_log()
        auth = {"kind": "evidence-cert", "cert": cert,
                "artifact_bytes": _canonical({"x": 1}),
                "artifact_signature": bytes(
                    ed.sign(seed, _canonical({"x": 1}))),
                "approval_id": APPROVAL, "intent_digest": INTENT,
                "ca_public_key": bytes(ca_pub), "verify_time": NOW}
        other = hashlib.sha256(_canonical({"y": 2})).hexdigest()
        self.assertCode("evbundle-unauthorized-producer", log.submit,
                       other, producer_auth=auth)

    def test_inclusion_proof_forgery(self):
        sub, log, _cert, _seed, _ca_pub = self._submit()
        receipt = sub["transparency_receipt"]
        checkpoint = {"log_id": receipt["log_id"],
                      "tree_size": receipt["tree_size"],
                      "root": receipt["root"],
                      "integrated_time": receipt["integrated_time"]}
        bad_proof = dict(receipt["inclusion_proof"])
        bad_proof["hashes"] = ["ff" * 32 for _ in
                               bad_proof["hashes"]] or ["ff" * 32]
        self.assertCode(
            "evbundle-inclusion-unverified", log.verify_inclusion,
            sub["sealed"]["artifact"]["artifact_digest"], bad_proof,
            checkpoint)

    def test_checkpoint_root_mutation(self):
        sub, log, _cert, _seed, _ca_pub = self._submit()
        receipt = sub["transparency_receipt"]
        bad = {"log_id": receipt["log_id"],
               "tree_size": receipt["tree_size"],
               "root": "ff" * 32,
               "integrated_time": receipt["integrated_time"]}
        self.assertCode("evbundle-checkpoint-invalid",
                       log.verify_checkpoint, bad)

    def test_checkpoint_foreign_log(self):
        sub, log_a, _cert, _seed, _ca_pub = self._submit()
        receipt = sub["transparency_receipt"]
        checkpoint = {"log_id": receipt["log_id"],
                      "tree_size": receipt["tree_size"],
                      "root": receipt["root"],
                      "integrated_time": receipt["integrated_time"]}
        log_b = self.make_log(log_id="other-log")
        self.assertCode("evbundle-checkpoint-invalid",
                       log_b.verify_checkpoint, checkpoint)

    def test_consistency_divergent_logs(self):
        # Two logs with different log_ids: the pair is not consistent.
        log_a = self.make_log(log_id="log-a")
        log_b = self.make_log(log_id="log-b")
        digest_a = "aa" * 32
        digest_b = "bb" * 32
        log_a._leaves.append(bytes.fromhex(digest_a))
        log_b._leaves.append(bytes.fromhex(digest_b))
        chk_a = log_a._checkpoint(1)
        chk_b = log_b._checkpoint(1)
        self.assertCode("evbundle-consistency-invalid",
                       log_b.verify_consistency, chk_a, chk_b)

    def test_consistency_shrink(self):
        # Both checkpoints valid on the SAME log, but old > new.
        _ca, cert, seed, _pub, ca_pub = self.harness()
        log = self.make_log()
        subs = []
        for body in ({"a": 1}, {"b": 2}):
            subs.append(eb2.submit_evidence(
                **self.seal_kwargs(cert, seed, ca_pub, body=body),
                audit_log_path=self.audit_path, transparency_log=log))
        chks = []
        for sub in subs:
            r = sub["transparency_receipt"]
            chks.append({"log_id": r["log_id"], "tree_size": r["tree_size"],
                         "root": r["root"],
                         "integrated_time": r["integrated_time"]})
        self.assertIs(log.verify_consistency(chks[0], chks[1]), True)
        self.assertCode("evbundle-consistency-invalid",
                       log.verify_consistency, chks[1], chks[0])

    def test_transparency_outage_fails_closed(self):
        _ca, cert, seed, _pub, ca_pub = self.harness()

        class _Down(eb2.TransparencyLogProvider):
            provider_name = "down"

            def submit(self, digest, *, producer_auth=None):
                raise RuntimeError("connection refused")

        with self.assertRaises(eb2.EvidenceBundleV2Error) as ctx:
            eb2.submit_evidence(
                **self.seal_kwargs(cert, seed, ca_pub),
                audit_log_path=self.audit_path,
                transparency_log=_Down())
        self.assertEqual(ctx.exception.code,
                         "evbundle-transparency-unavailable")

    def test_submit_malformed_wrong_kind(self):
        self.assertCode("evbundle-malformed", eb2.verify_submission,
                       submission={"kind": "nope"},
                       audit_log_path=self.audit_path,
                       ca_public_key=b"\x00" * 32, verify_time=NOW,
                       transparency_log=self.make_log())


class LegacyStabilityTests(V2Base):
    def test_v1_bundle_and_receipts_byte_stable(self):
        from gov import evidence_bundle as eb1
        from gov import corroboration_receipt as cr
        body = {"decision": "deny", "subjects": ["agent-7"]}
        self.assertEqual(eb1.canonical(body), _canonical(body))
        st = {"_type": "https://in-toto.io/Statement/v1",
              "predicateType": "https://sasanam.dev/corrob/v1",
              "subject": [{"name": "decision",
                           "digest": {"sha256": "ab" * 32}}],
              "predicate": {"verdict": "allow"}}
        self.assertEqual(cr.dsse_envelope(st), cr.dsse_envelope(dict(st)))


class TaxonomyTests(unittest.TestCase):
    def test_evbundle_codes_registered(self):
        for code, severity in EXPECTED_EVBUNDLE_CODES:
            self.assertIn(code, TAXONOMY)
            self.assertEqual(TAXONOMY[code]["domain"], "evbundle")
            self.assertEqual(TAXONOMY[code]["severity"], severity)

    def test_taxonomy_pin_1411_on_raw_literals(self):
        # Wave-260: duplicates are invisible to len(TAXONOMY); assert on
        # the raw source literals instead. Lane-local pin: 1325 + 8.
        import gov.decision_codes as dc
        with open(dc.__file__, encoding="utf-8") as f:
            src = f.read()
        literals = re.findall(r'"code": \'([^\']+)\'', src)
        self.assertEqual(len(literals), 1828)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        self.assertEqual(len(set(literals)), 1828)  # zero duplicates; Wave-284 merge: pin 1588 -> 1621 (+1 discovery-emit-failed +4 manifest-* +7 guac-graph-* +8 envelope-*/recipient-policy +6 sandbox-policy-* +8 keyset-*).; Wave-286 merge: pin 1641 -> 1660; Wave-287 merge: pin 1660 -> 1684 (+7 tsa-* +7 evidence-provenance +10 trustvec-*) (+1 manifest-regex-unsafe +1 keyset-pin-key-invalid +6 receipt-* +11 toolcall-*).; Wave-288 merge: pin 1684 -> 1706 (+16: 1 toolcall-exception-scope-mismatch +1 toolcall-regex-unsafe +1 toolcall-invalid-call +7 admission-* +6 posture-*); Wave-289 merge: pin 1700 -> 1706 (+6 challenge-*); Wave-293 lane 2: pin 1723 -> 1726 (+3 toolcall-*: sequence-violated, secret-in-args, rule-compile-invalid); wave-293 merge: pin 1726 -> 1742 (+4 keysuccession-*); Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        self.assertEqual(len(dc.TAXONOMY), 1828)  # Wave-295 lane 1: pin 1742 -> 1743 (+1 toolcall-secret-scan-incomplete); Wave-295 merge: pin 1743 -> 1750 (+8: 1 toolcall-secret-scan-incomplete + 3 toolcall-predicate-* + 4 coord-state-*); Wave-299 merge: pin 1780 -> 1797 (+17 codes: 4 delegation-* + 4 delegation-ticket-* + 3 supervision-capability-* + 3 delegation-revocation-* + 3 delegation-identity-*)
        for code, _sev in EXPECTED_EVBUNDLE_CODES:
            self.assertEqual(src.count("\"code\": '%s'" % code), 1,
                             "code literal %s must appear exactly once"
                             % code)


if __name__ == "__main__":
    unittest.main()
