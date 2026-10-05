"""Unit tests for gov.evidence_sigstore (wave-311 lane D).

Sigstore Bundle v0.3-compatible distribution for the offline evidence
bundle (prospectus build-order step 3,
``research/prospecting/w310_offline_verifier_auditor_ux.md``): the bundle
carries the sealed in-toto statement's DSSE envelope (Sigstore protobuf
JSON shape: base64 payload, base64 signatures) + an inline witness /
transparency entry (OUR OWN Rekor-pattern entry issued by a local witness
key -- NOT the public Rekor service; $0, offline-first) + an optional
RFC 3161 timestamp token field (carried, not cryptographically verified
in this lane; the bundle MUST verify without it).

These tests pin the bundle seam, RED-FIRST:

- the v0.3-compatible wire shape (mediaType / verificationMaterial /
  dsseEnvelope, base64 sigs, keyid-as-hint);
- the witness entry binds artifact digest + signature + key
  (CVE-2026-22703 lesson) and its integratedTime is checked against a
  caller-pinned validity window (CVE-2026-24122 analogue);
- content checks (payloadType, statement shape, predicateType, subject
  digest) are ALWAYS ON, never opt-in (CVE-2026-39395 lesson);
- a crash/malformed input never emits a success signal
  (CVE-2026-44310 lesson): every refusal is a coded EnvelopeError;
- the forgery probes below are written FIRST and must refuse CODED;
- the third-party acceptance test verifies with stdlib json/base64/
  hashlib + the spec PAE formula + the raw Ed25519 primitive only --
  no Sasanam envelope code ("sell evidence, not the engine");
- the cosign interop gate checks the bundle against cosign's documented
  bundle expectations structurally, and -- when a cosign binary is
  available -- runs cosign's real ``verify-blob`` path over our exact
  envelope bytes.
"""

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from gov import dsse_envelope as _dsse
from gov import ed25519 as _ed25519
from gov import evidence_dsse
from gov import evidence_intoto
from gov.signing import Ed25519Signer, Ed25519Verifier

MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
PT = evidence_dsse.EVIDENCE_DSSE_PAYLOAD_TYPE  # application/vnd.in-toto+json
INTOTO_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://sasanam.dev/predicate/evidence-bundle/v1"
WITNESS_KIND = "sasanam-witness"
WITNESS_VERSION = "0.0.1"

BUNDLE = b'{"bundle":"synthetic-test-bytes-311"}'
OTHER = b'{"bundle":"different-bytes-312"}'
CLAIMS = {"window": "2026-10-03", "tip": "cd" * 16, "decisions": 7}

# Fixed witness clock for deterministic tests (2026-10-03T~15:30Z).
T0 = 1791528600
VALIDITY = (1791528000, 1791530000)  # pinned witness-key validity window


def _signers(n, base=41):
    return [Ed25519Signer(bytes([base + i]) * 32) for i in range(n)]


def _verifiers(signers):
    return [Ed25519Verifier(s.public_key, s.key_id) for s in signers]


def _witness(base=77):
    return Ed25519Signer(bytes([base]) * 32)


def _witness_verifier(witness):
    return Ed25519Verifier(witness.public_key, witness.key_id)


def _sealed_bundle(signers=None, witness=None, bundle_bytes=BUNDLE,
                   claims=CLAIMS, rfc3161_token=None,
                   integrated_time=T0):
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    stmt = evidence_intoto.build_statement(bundle_bytes, claims)
    env = evidence_intoto.seal_statement(stmt, signers)
    from gov import evidence_sigstore
    return evidence_sigstore.seal_sigstore_bundle(
        env, signers, witness, rfc3161_token=rfc3161_token,
        integrated_time=integrated_time)


def _open(bundle, bundle_bytes=BUNDLE, signers=None, witness=None,
          threshold=1, validity=VALIDITY):
    from gov import evidence_sigstore
    signers = _signers(1) if signers is None else signers
    witness = _witness() if witness is None else witness
    return evidence_sigstore.open_sigstore_bundle(
        bundle, bundle_bytes, _verifiers(signers),
        _witness_verifier(witness), threshold=threshold,
        witness_validity=validity)


def _reason(exc):
    return getattr(exc, "reason", str(exc))


class TestBundleShape(unittest.TestCase):
    def test_media_type_pinned(self):
        bundle = _sealed_bundle()
        self.assertEqual(bundle["mediaType"], MEDIA_TYPE)
        self.assertEqual(bundle["mediaType"],
                         "application/vnd.dev.sigstore.bundle.v0.3+json")

    def test_top_level_fields(self):
        bundle = _sealed_bundle()
        self.assertEqual(set(bundle),
                         {"mediaType", "verificationMaterial",
                          "dsseEnvelope"})

    def test_dsse_envelope_sigstore_shape(self):
        # Sigstore protobuf JSON: base64 payload, base64 signatures
        # (NOT our native hex) -- this is the interop surface.
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers)
        env = bundle["dsseEnvelope"]
        self.assertEqual(set(env), {"payload", "payloadType", "signatures"})
        self.assertEqual(env["payloadType"], PT)
        body = base64.b64decode(env["payload"])  # must be valid base64
        self.assertTrue(body.startswith(b"{"))
        self.assertEqual(len(env["signatures"]), 1)
        entry = env["signatures"][0]
        self.assertEqual(set(entry), {"keyid", "sig"})
        self.assertEqual(entry["keyid"], signers[0].key_id)
        sig = base64.b64decode(entry["sig"])  # base64, 64 bytes
        self.assertEqual(len(sig), 64)

    def test_envelope_payload_is_statement_bytes(self):
        signers = _signers(1)
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        bundle = _sealed_bundle(signers=signers)
        body = base64.b64decode(bundle["dsseEnvelope"]["payload"])
        self.assertEqual(body, evidence_intoto.statement_bytes(stmt))

    def test_verification_material_carries_signer_key(self):
        # Bundle v0.3 form (1): PublicKeyIdentifier carries ONLY hint.
        # The raw key travels out-of-band; the hint names the signer.
        from gov import sigstore_bundle as _sigbundle
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers)
        vm = bundle["verificationMaterial"]
        self.assertIn("publicKey", vm)
        self.assertIn("tlogEntries", vm)
        self.assertEqual(set(vm["publicKey"]), {"hint"})
        self.assertEqual(vm["publicKey"]["hint"],
                         _sigbundle.key_hint(signers[0].public_key))

    def test_witness_entry_shape(self):
        bundle = _sealed_bundle()
        entries = bundle["verificationMaterial"]["tlogEntries"]
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(set(entry),
                         {"logIndex", "logId", "kindVersion",
                          "integratedTime", "inclusionPromise",
                          "canonicalizedBody"})
        self.assertEqual(entry["kindVersion"],
                         {"kind": WITNESS_KIND, "version": WITNESS_VERSION})
        self.assertEqual(entry["logIndex"], "0")
        # integratedTime is the sealer's clock, pinned by the test.
        self.assertEqual(entry["integratedTime"], str(T0))
        set_b64 = entry["inclusionPromise"]["signedEntryTimestamp"]
        self.assertEqual(len(base64.b64decode(set_b64)), 64)
        # canonicalizedBody is base64 of canonical JSON.
        cbody = base64.b64decode(entry["canonicalizedBody"])
        self.assertEqual(cbody, json.dumps(
            json.loads(cbody.decode("utf-8")), sort_keys=True,
            separators=(",", ":"), ensure_ascii=True).encode("utf-8"))

    def test_witness_body_binds_artifact_signature_key(self):
        # CVE-2026-22703: the entry binds artifact digest + signature +
        # key -- never "a valid entry" alone.
        signers = _signers(1)
        witness = _witness()
        bundle = _sealed_bundle(signers=signers, witness=witness)
        entry = bundle["verificationMaterial"]["tlogEntries"][0]
        spec = json.loads(
            base64.b64decode(entry["canonicalizedBody"]).decode("utf-8"))["spec"]
        payload = base64.b64decode(bundle["dsseEnvelope"]["payload"])
        self.assertEqual(spec["artifactDigest"],
                         hashlib.sha256(payload).hexdigest())
        self.assertEqual(spec["signatures"],
                         bundle["dsseEnvelope"]["signatures"])
        self.assertEqual(base64.b64decode(spec["publicKey"]["rawBytes"]),
                         signers[0].public_key)
        # logId names the witness key: sha256(pub), base64.
        self.assertEqual(base64.b64decode(entry["logId"]["keyId"]),
                         hashlib.sha256(witness.public_key).digest())

    def test_no_token_by_default(self):
        bundle = _sealed_bundle()
        vm = bundle["verificationMaterial"]
        self.assertNotIn("timestampVerificationData", vm)

    def test_token_carried_when_given(self):
        token = b"fake-rfc3161-timestampresp-bytes"
        bundle = _sealed_bundle(rfc3161_token=token)
        ts = bundle["verificationMaterial"]["timestampVerificationData"][
            "rfc3161Timestamps"]
        self.assertEqual(len(ts), 1)
        self.assertEqual(base64.b64decode(ts[0]["signedTimestamp"]), token)

    def test_seal_refuses_malformed_token(self):
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _sealed_bundle(rfc3161_token="not-bytes")
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")

    def test_seal_refuses_empty_signers(self):
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, _signers(1))
        from gov import evidence_sigstore
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_sigstore.seal_sigstore_bundle(env, [], _witness())

    def test_seal_refuses_wrong_payload_type(self):
        from gov import evidence_sigstore
        env = _dsse.seal(b"{}", "application/json", _signers(1))
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_sigstore.seal_sigstore_bundle(env, _signers(1),
                                                   _witness())
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")


class TestRoundTrip(unittest.TestCase):
    def test_open_returns_statement(self):
        signers = _signers(1)
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        bundle = _sealed_bundle(signers=signers)
        got = _open(bundle, signers=signers)
        self.assertEqual(got["statement"], stmt)

    def test_open_returns_verified_payload_bytes(self):
        bundle = _sealed_bundle()
        got = _open(bundle)
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        self.assertEqual(got["payload"],
                         evidence_intoto.statement_bytes(stmt))

    def test_open_reports_key_ids_and_witness(self):
        signers = _signers(1)
        witness = _witness()
        bundle = _sealed_bundle(signers=signers, witness=witness)
        got = _open(bundle, signers=signers, witness=witness)
        self.assertEqual(got["key_ids"], [signers[0].key_id])
        self.assertEqual(got["payload_sha256"],
                         hashlib.sha256(got["payload"]).hexdigest())
        w = got["witness"]
        self.assertEqual(w["integrated_time"], T0)
        self.assertEqual(w["validity_window"], VALIDITY)
        self.assertIn("time_source", w)
        self.assertEqual(w["witness_key_id"], witness.key_id)

    def test_open_accepts_wire_bytes(self):
        bundle = _sealed_bundle()
        wire = json.dumps(bundle).encode("utf-8")
        got = _open(wire)
        self.assertEqual(got["statement"]["predicate"], CLAIMS)

    def test_open_with_token_reports_presence(self):
        bundle = _sealed_bundle(rfc3161_token=b"tok-bytes")
        got = _open(bundle)
        self.assertIs(got["rfc3161_present"], True)

    def test_open_without_token_reports_absence(self):
        bundle = _sealed_bundle()
        got = _open(bundle)
        self.assertIs(got["rfc3161_present"], False)

    def test_threshold_2_of_3(self):
        signers = _signers(3)
        bundle = _sealed_bundle(signers=signers)
        got = _open(bundle, signers=signers, threshold=2)
        self.assertEqual(len(got["key_ids"]), 3)

    def test_keyid_is_hint(self):
        # Stripped keyids fall back to try-all; authentication is not
        # weakened (inherited DSSE discipline). The witness binds the
        # exact wire signatures, so the envelope is re-stripped and
        # re-sealed before distribution.
        signers = _signers(1)
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        for entry in env["signatures"]:
            entry.pop("keyid", None)
        from gov import evidence_sigstore
        rebound = evidence_sigstore.seal_sigstore_bundle(
            env, signers, _witness(), integrated_time=T0)
        self.assertNotIn("keyid",
                         rebound["dsseEnvelope"]["signatures"][0])
        got = _open(rebound, signers=signers)
        self.assertEqual(got["statement"]["predicate"], CLAIMS)


class TestBreakProbes(unittest.TestCase):
    """Break-first: every forgery refuses CODED. These probes are
    written before the implementation and must fail closed -- a naive
    verifier that skipped a check would let one through."""

    def test_tampered_payload_refuses_coded(self):
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers)
        tampered = copy.deepcopy(bundle)
        body = bytearray(base64.b64decode(tampered["dsseEnvelope"]["payload"]))
        body[10] ^= 0x01
        tampered["dsseEnvelope"]["payload"] = base64.b64encode(
            bytes(body)).decode("ascii")
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(tampered, signers=signers)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-signature-invalid")

    def test_swapped_signature_refuses_coded(self):
        # Attacker swaps in a VALID signature from an untrusted key over
        # the same PAE: only the signature check catches it.
        signers = _signers(1)
        attacker = _signers(1, base=99)
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        payload = base64.b64decode(env["payload"])
        pae = _dsse.pae(env["payloadType"], payload)
        evil_sig = attacker[0].sign(pae)
        bundle = _sealed_bundle(signers=signers)
        swapped = copy.deepcopy(bundle)
        swapped["dsseEnvelope"]["signatures"] = [{
            "keyid": attacker[0].key_id,
            "sig": base64.b64encode(evil_sig).decode("ascii"),
        }]
        # Rebind the witness entry to the swapped envelope would need
        # the witness key -- the attacker does not have it; the
        # signature check must refuse first.
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(swapped, signers=signers)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-signature-invalid")

    def test_wrong_predicate_refuses_coded(self):
        # CVE-2026-39395: content checks are always on, never opt-in. A
        # well-signed statement under the WRONG predicateType must
        # refuse at open even though the DSSE signature verifies.
        signers = _signers(1)
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        stmt["predicateType"] = "https://example.com/evil/v9"
        env = evidence_dsse.seal_evidence_bundle(
            evidence_intoto.statement_bytes(stmt), signers)
        bundle = _sealed_bundle(signers=signers)
        evil = copy.deepcopy(bundle)
        evil["dsseEnvelope"] = {
            "payload": env["payload"],
            "payloadType": env["payloadType"],
            "signatures": [{
                "keyid": s["keyid"],
                "sig": base64.b64encode(
                    bytes.fromhex(s["sig"])).decode("ascii"),
            } for s in env["signatures"]],
        }
        # Witness entry is dummy: the content check must fire before the
        # witness stage is even reached.
        evil["verificationMaterial"]["tlogEntries"] = [{"bogus": True}]
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(evil, signers=signers)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-predicate-refused")

    def test_wrong_subject_bundle_refuses_coded(self):
        # A valid signature over a statement about bundle A does not
        # verify as bundle B (authentication precedes binding).
        bundle = _sealed_bundle()
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle, bundle_bytes=OTHER)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-subject-mismatch")

    def test_missing_witness_entry_refuses_coded(self):
        bundle = _sealed_bundle()
        missing = copy.deepcopy(bundle)
        missing["verificationMaterial"]["tlogEntries"] = []
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(missing)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-missing")

    def test_expired_witness_refuses_coded(self):
        # CVE-2026-24122 analogue: integratedTime outside the pinned
        # validity window refuses -- before AND after the window.
        for bad_t in (VALIDITY[0] - 1, VALIDITY[1] + 1):
            bundle = _sealed_bundle(integrated_time=bad_t)
            with self.assertRaises(_dsse.EnvelopeError) as ctx:
                _open(bundle)
            self.assertEqual(_reason(ctx.exception),
                             "evidence-bundle-witness-expired")

    def test_tampered_witness_body_refuses_coded(self):
        # Flipping a byte in the canonicalizedBody breaks the
        # artifact/signature/key binding (CVE-2026-22703).
        bundle = _sealed_bundle()
        tampered = copy.deepcopy(bundle)
        entry = tampered["verificationMaterial"]["tlogEntries"][0]
        raw = bytearray(base64.b64decode(entry["canonicalizedBody"]))
        raw[20] ^= 0x01
        entry["canonicalizedBody"] = base64.b64encode(bytes(raw)).decode(
            "ascii")
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(tampered)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-unbound")

    def test_publickey_unknown_field_refuses_coded(self):
        # Bundle v0.3 form (1): PublicKeyIdentifier has only 'hint'.
        # Unknown fields are refused -- strict protobuf-JSON parsers
        # reject them, so accepting them would fork the wire shape.
        bundle = _sealed_bundle()
        tampered = copy.deepcopy(bundle)
        tampered["verificationMaterial"]["publicKey"]["rawBytes"] = "AA=="
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(tampered)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-verification-material")

    def test_hint_spoof_refuses_coded(self):
        # A hint naming a key that did not authenticate the bundle is
        # refused: the hint is informational, never authority, and it
        # must not lie.
        bundle = _sealed_bundle()
        tampered = copy.deepcopy(bundle)
        tampered["verificationMaterial"]["publicKey"]["hint"] = "ff" * 32
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(tampered)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-hint-mismatch")

    def test_empty_hint_accepts(self):
        # The spike-proven cosign shape {"publicKey": {}} verifies: the
        # key is pinned out-of-band by the auditor.
        bundle = _sealed_bundle()
        bare = copy.deepcopy(bundle)
        bare["verificationMaterial"]["publicKey"] = {}
        got = _open(bare)
        self.assertEqual(got["statement"]["predicate"], CLAIMS)

    def test_wrong_witness_key_refuses_coded(self):
        # Entry witnessed by an attacker's key: the logId does not name
        # the pinned witness key, so the binding check refuses before
        # the SET is even attempted.
        attacker_witness = _witness(base=78)
        bundle = _sealed_bundle(witness=attacker_witness)
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle, witness=_witness())
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-unbound")

    def test_tampered_set_refuses_coded(self):
        # The entry is bound to our witness key but the SET itself is
        # forged: the signature check catches it.
        bundle = _sealed_bundle()
        tampered = copy.deepcopy(bundle)
        entry = tampered["verificationMaterial"]["tlogEntries"][0]
        raw = bytearray(base64.b64decode(
            entry["inclusionPromise"]["signedEntryTimestamp"]))
        raw[0] ^= 0x01
        entry["inclusionPromise"]["signedEntryTimestamp"] = (
            base64.b64encode(bytes(raw)).decode("ascii"))
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(tampered)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-signature-invalid")

    def test_witness_kind_spoof_refuses_coded(self):
        bundle = _sealed_bundle()
        spoofed = copy.deepcopy(bundle)
        entry = spoofed["verificationMaterial"]["tlogEntries"][0]
        entry["kindVersion"] = {"kind": "hashedrekord", "version": "0.0.1"}
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(spoofed)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-unsupported")

    def test_bad_media_type_refuses_coded(self):
        bundle = _sealed_bundle()
        bad = copy.deepcopy(bundle)
        bad["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.2+json"
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bad)
        self.assertEqual(_reason(ctx.exception), "evidence-bundle-malformed")

    def test_malformed_token_refuses_coded(self):
        bundle = _sealed_bundle(rfc3161_token=b"tok")
        bad = copy.deepcopy(bundle)
        bad["verificationMaterial"]["timestampVerificationData"][
            "rfc3161Timestamps"] = [{"signedTimestamp": "!!!not-base64!!!"}]
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bad)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-timestamp-malformed")

    def test_threshold_not_met_refuses_coded(self):
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers)
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle, signers=signers, threshold=2)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-signature-invalid")

    def test_garbage_bundle_refuses_coded(self):
        for bad in ({}, {"mediaType": MEDIA_TYPE}, "not-json{{{",
                    b"\x00\x01", []):
            with self.assertRaises(_dsse.EnvelopeError) as ctx:
                _open(bad)
            self.assertEqual(_reason(ctx.exception),
                             "evidence-bundle-malformed")

    def test_no_verifiers_refuses(self):
        from gov import evidence_sigstore
        bundle = _sealed_bundle()
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_sigstore.open_sigstore_bundle(
                bundle, BUNDLE, [], _witness_verifier(_witness()),
                witness_validity=VALIDITY)

    def test_witness_validity_required(self):
        # No silent downgrade: the validity window is a required
        # keyword -- without it the time check cannot run.
        from gov import evidence_sigstore
        bundle = _sealed_bundle()
        with self.assertRaises(_dsse.EnvelopeError):
            evidence_sigstore.open_sigstore_bundle(
                bundle, BUNDLE, _verifiers(_signers(1)),
                _witness_verifier(_witness()))


class TestF416TotalInt64Parsing(unittest.TestCase):
    """Wave-331 lane 2 (F416): int64-as-string parsing is TOTAL.

    _parse_int64_as_string accepts only short ASCII digit strings and
    refuses coded evidence-bundle-malformed on everything else -- a
    bare ValueError (digit-limit, non-ASCII digits) can never escape.
    The witness SET is verified BEFORE integratedTime/logIndex are
    touched, so a hostile bundle's garbage fields hit the witness
    refusal first.
    """

    def test_parse_valid(self):
        from gov import evidence_sigstore as es
        self.assertEqual(es._parse_int64_as_string("0", "f"), 0)
        self.assertEqual(es._parse_int64_as_string("42", "f"), 42)
        self.assertEqual(
            es._parse_int64_as_string(str(2 ** 63 - 1), "f"), 2 ** 63 - 1)

    def test_parse_overlong_refuses_coded(self):
        # F416: >4300-digit strings used to pass isdigit() and crash
        # int() with a bare ValueError.
        from gov import evidence_sigstore as es
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            es._parse_int64_as_string("9" * 5000, "f")
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")

    def test_parse_non_ascii_digits_refuses_coded(self):
        # F415 class: str.isdigit() admits "²" but int() rejects it.
        from gov import evidence_sigstore as es
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            es._parse_int64_as_string("1²3", "f")
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")

    def test_parse_wrong_type_and_empty_refuse_coded(self):
        from gov import evidence_sigstore as es
        for bad in (None, 123, "", b"42", " 42", "+42", "4_2"):
            with self.assertRaises(_dsse.EnvelopeError,
                                   msg="value %r" % (bad,)):
                es._parse_int64_as_string(bad, "f")

    def test_parse_beyond_int64_refuses_coded(self):
        from gov import evidence_sigstore as es
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            es._parse_int64_as_string(str(2 ** 63), "f")
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")

    def test_end_to_end_overlong_integratedtime_refuses_coded(self):
        # P1a at unit level: sealed-valid bundle, hostile integratedTime.
        bundle = _sealed_bundle()
        bundle["verificationMaterial"]["tlogEntries"][0][
            "integratedTime"] = "9" * 5000
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")

    def test_end_to_end_overlong_logindex_refuses_coded(self):
        # P1b at unit level: log-backed bundle, hostile logIndex.
        from gov import evidence_sigstore, witness_log
        signers = _signers(1)
        witness = _witness()
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        wlog = witness_log.WitnessLog(witness.public_key)
        bundle = evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        bundle["verificationMaterial"]["tlogEntries"][0][
            "logIndex"] = "9" * 5000
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle, signers=signers, witness=witness)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")

    def test_witness_refusal_precedes_time_parse(self):
        # F416(b): a bundle that is hostile in BOTH dimensions (garbage
        # integratedTime AND a forged SET) must hit the witness refusal
        # first -- the time/index fields are not trusted until the SET
        # verifies.
        bundle = _sealed_bundle()
        entry = bundle["verificationMaterial"]["tlogEntries"][0]
        entry["integratedTime"] = "9" * 5000
        raw = bytearray(base64.b64decode(
            entry["inclusionPromise"]["signedEntryTimestamp"]))
        raw[0] ^= 0x01
        entry["inclusionPromise"]["signedEntryTimestamp"] = (
            base64.b64encode(bytes(raw)).decode("ascii"))
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-signature-invalid")

    def test_checkpoint_refusal_precedes_index_parse(self):
        # F416(b): garbage logIndex + forged checkpoint -> the witness
        # checkpoint refusal comes first, never the index conversion.
        from gov import evidence_sigstore, witness_log
        signers = _signers(1)
        witness = _witness()
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        wlog = witness_log.WitnessLog(witness.public_key)
        bundle = evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        entry = bundle["verificationMaterial"]["tlogEntries"][0]
        entry["logIndex"] = "9" * 5000
        raw = bytearray(base64.b64decode(
            entry["inclusionProof"]["checkpointSignature"]))
        raw[0] ^= 0x01
        entry["inclusionProof"]["checkpointSignature"] = (
            base64.b64encode(bytes(raw)).decode("ascii"))
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            _open(bundle, signers=signers, witness=witness)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-witness-checkpoint-invalid")

    def test_never_bare_valueerror(self):
        # The totality property: no input drawn from the hostile shapes
        # may escape as a bare ValueError.
        from gov import evidence_sigstore as es
        hostile = ["9" * 5000, "1²3", "１２３", "", " ", "\t42",
                   str(2 ** 63), "-" + "9" * 19, None, 3.5, ["4"]]
        for h in hostile:
            try:
                es._parse_int64_as_string(h, "f")
            except _dsse.EnvelopeError:
                pass  # coded refusal: the only acceptable failure
            except ValueError as exc:
                # A bare ValueError must never escape; EnvelopeError IS
                # a ValueError subclass, so exclude the coded path.
                if not isinstance(exc, _dsse.EnvelopeError):
                    self.fail("bare ValueError escaped for %r" % (h,))


class TestThirdPartyAcceptance(unittest.TestCase):
    """The acceptance test for "sell evidence, not the engine".

    Verify a sealed Sigstore bundle the way a third party would: stdlib
    JSON + base64 + hashlib, the DSSE spec's PAE formula, and the raw
    Ed25519 primitive. No ``gov.dsse_envelope``, no
    ``gov.evidence_dsse``, no ``gov.evidence_intoto``, no
    ``gov.evidence_sigstore`` anywhere in the verify path -- only the
    signer's and the witness's public key bytes (which any consumer
    holds, pinned out-of-band like the registystack pattern) and the
    documented wire format.
    """

    def _third_party_verify(self, wire, expected_bundle_bytes, dsse_pub,
                            witness_pub):
        parsed = json.loads(wire.decode("utf-8"))

        # 1. Bundle media type per the Sigstore bundle v0.3 contract.
        assert parsed["mediaType"] == MEDIA_TYPE, parsed["mediaType"]

        # 2. DSSE envelope: payloadType bound, payload bytes extracted.
        env = parsed["dsseEnvelope"]
        assert env["payloadType"] == PT, env["payloadType"]
        body = base64.b64decode(env["payload"])

        # 3. PAE hand-built from the spec formula (independent of
        # gov.dsse_envelope.pae).
        ptype = env["payloadType"].encode("utf-8")
        pae = (b"DSSEv1 " + str(len(ptype)).encode("ascii") + b" "
               + ptype + b" " + str(len(body)).encode("ascii")
               + b" " + body)

        # 4. Every listed signature verifies with the raw primitive;
        # keyid is a hint only -- the key tried is the pinned one.
        verified = 0
        for entry in env["signatures"]:
            sig = base64.b64decode(entry["sig"])
            if _ed25519.verify(dsse_pub, pae, sig) is True:
                verified += 1
        assert verified >= 1, "no DSSE signature verified"

        # 5. The statement is plain in-toto JSON: subject digest-matched
        # against the bundle bytes we hold.
        statement = json.loads(body.decode("utf-8"))
        assert statement["_type"] == INTOTO_TYPE
        assert statement["predicateType"] == PREDICATE_TYPE
        assert (statement["subject"][0]["digest"]["sha256"]
                == hashlib.sha256(expected_bundle_bytes).hexdigest())
        predicate = statement["predicate"]

        # 6. The witness entry binds artifact + signature + key
        # (CVE-2026-22703): re-derive the canonical body independently
        # from the envelope's own wire fields and require byte-equality.
        entry = parsed["verificationMaterial"]["tlogEntries"][0]
        assert entry["kindVersion"] == {"kind": WITNESS_KIND,
                                       "version": WITNESS_VERSION}
        cbody = base64.b64decode(entry["canonicalizedBody"])
        expect_body = {
            "apiVersion": "0.0.1",
            "kind": WITNESS_KIND,
            "spec": {
                "artifactDigest": hashlib.sha256(body).hexdigest(),
                "signatures": env["signatures"],
                "publicKey": {
                    "rawBytes": base64.b64encode(dsse_pub).decode("ascii"),
                    "keyDetails": "PKIX_ED25519",
                },
            },
        }
        expect_cbody = json.dumps(
            expect_body, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True).encode("utf-8")
        assert cbody == expect_cbody, "witness body binding broken"

        # 7. The witness SET verifies with the raw primitive against the
        # pinned witness key; logId names that same key.
        set_sig = base64.b64decode(
            entry["inclusionPromise"]["signedEntryTimestamp"])
        assert _ed25519.verify(witness_pub, cbody, set_sig) is True
        assert (base64.b64decode(entry["logId"]["keyId"])
                == hashlib.sha256(witness_pub).digest())

        return {"predicate": predicate,
                "verified_signatures": verified,
                "integrated_time": int(entry["integratedTime"])}

    def test_verify_with_stdlib_only(self):
        signers = _signers(1)
        witness = _witness()
        bundle = _sealed_bundle(signers=signers, witness=witness,
                                rfc3161_token=b"tok")
        wire = json.dumps(bundle).encode("utf-8")
        got = self._third_party_verify(wire, BUNDLE, signers[0].public_key,
                                       witness.public_key)
        self.assertEqual(got["predicate"], CLAIMS)
        self.assertEqual(got["verified_signatures"], 1)
        self.assertEqual(got["integrated_time"], T0)

    def test_third_party_catches_tampered_payload(self):
        signers = _signers(1)
        witness = _witness()
        bundle = _sealed_bundle(signers=signers, witness=witness)
        tampered = copy.deepcopy(bundle)
        body = bytearray(base64.b64decode(tampered["dsseEnvelope"]["payload"]))
        body[10] ^= 0x01
        tampered["dsseEnvelope"]["payload"] = base64.b64encode(
            bytes(body)).decode("ascii")
        wire = json.dumps(tampered).encode("utf-8")
        with self.assertRaises(AssertionError):
            self._third_party_verify(wire, BUNDLE, signers[0].public_key,
                                     witness.public_key)


def _ed25519_spki_pem(pub):
    """SubjectPublicKeyInfo PEM for a 32-byte Ed25519 key (stdlib only).

    DER: SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING pub }.
    """
    assert isinstance(pub, bytes) and len(pub) == 32
    alg = b"\x30\x05\x06\x03\x2b\x65\x70"          # SEQ { OID Ed25519 }
    bitstr = b"\x03\x21\x00" + pub                # BIT STRING, 0 unused
    spki = b"\x30\x2a" + alg + bitstr              # SEQ, len 42
    b64 = base64.encodebytes(spki).decode("ascii")
    return ("-----BEGIN PUBLIC KEY-----\n" + b64.strip()
            + "\n-----END PUBLIC KEY-----\n").encode("ascii")


def _cosign_binary():
    override = os.environ.get("COSIGN_BIN")
    if override and os.path.isfile(override) and os.access(override, os.X_OK):
        return override
    found = shutil.which("cosign")
    return found


class TestCosignInterop(unittest.TestCase):
    """Interop gate: our bundles must be consumable by third-party
    verification paths.

    Part 1 (always runs): the bundle JSON satisfies cosign's documented
    Sigstore Bundle v0.3 expectations -- mediaType, verificationMaterial
    (publicKey/tlogEntries/timestampVerificationData), dsseEnvelope
    (payload/payloadType/signatures with base64 sigs, keyid-as-hint).

    Part 2 (runs when OpenSSL is present): OpenSSL's REAL ``pkeyutl``
    path verifies our exact envelope PAE bytes against our Ed25519 key
    (exit 0), and refuses tampered bytes (non-zero exit) -- a genuine
    third-party (C, independent of our Python) check that the signature
    is a real Ed25519-over-spec-PAE signature.

    Part 3 (bounded attempt when a cosign binary is available via
    COSIGN_BIN or PATH): cosign's real ``verify-blob`` path over our
    exact envelope bytes. In THIS sandbox cosign 3.0.6 stalls after key
    load (its startup TUF init never completes behind the egress
    proxy -- verified via strace: proxy connect, then silence), so the
    attempt is time-bounded and skips honestly on timeout rather than
    hanging the suite. Where the network allows, it runs for real.
    """

    def test_bundle_meets_cosign_structural_expectations(self):
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers, rfc3161_token=b"tok")
        wire = json.dumps(bundle).encode("utf-8")
        parsed = json.loads(wire.decode("utf-8"))

        # mediaType: the v0.3 bundle contract.
        self.assertEqual(parsed["mediaType"], MEDIA_TYPE)

        # dsseEnvelope per the protobuf JSON mapping.
        env = parsed["dsseEnvelope"]
        self.assertEqual(set(env), {"payload", "payloadType",
                                    "signatures"})
        self.assertEqual(env["payloadType"], "application/vnd.in-toto+json")
        payload = base64.b64decode(env["payload"])
        self.assertTrue(len(payload) > 0)
        self.assertTrue(len(env["signatures"]) >= 1)
        for entry in env["signatures"]:
            sig = base64.b64decode(entry["sig"])
            self.assertEqual(len(sig), 64)  # Ed25519
            # keyid is a hint: present, non-empty string, never authority.
            self.assertIsInstance(entry.get("keyid"), str)
            self.assertTrue(entry["keyid"])

        # verificationMaterial per the protobuf JSON mapping: form (1)
        # PublicKeyIdentifier carries ONLY hint (strict protobuf-JSON
        # parsers reject unknown fields inside it). The hint names the
        # signing key; the raw key travels out-of-band.
        from gov import sigstore_bundle as _sigbundle
        vm = parsed["verificationMaterial"]
        self.assertEqual(set(vm["publicKey"]), {"hint"})
        self.assertEqual(vm["publicKey"]["hint"],
                         _sigbundle.key_hint(signers[0].public_key))
        self.assertTrue(len(vm["tlogEntries"]) >= 1)
        entry = vm["tlogEntries"][0]
        for field in ("logIndex", "logId", "kindVersion",
                      "integratedTime", "inclusionPromise",
                      "canonicalizedBody"):
            self.assertIn(field, entry)
        self.assertEqual(entry["kindVersion"]["kind"], WITNESS_KIND)
        int(entry["integratedTime"])  # int64-as-string
        base64.b64decode(
            entry["inclusionPromise"]["signedEntryTimestamp"])
        base64.b64decode(entry["canonicalizedBody"])
        base64.b64decode(entry["logId"]["keyId"])
        # Optional RFC 3161 carrier present and well-formed.
        ts = vm["timestampVerificationData"]["rfc3161Timestamps"]
        self.assertEqual(len(ts), 1)
        self.assertTrue(base64.b64decode(ts[0]["signedTimestamp"]))

    def test_openssl_verifies_our_envelope_bytes(self):
        # Third-party binary gate: OpenSSL (independent C
        # implementation) verifies the exact PAE bytes our bundle
        # carries. The PAE is hand-built from the spec formula, the PEM
        # from the SPKI DER -- no Sasanam code in the verify path.
        openssl = shutil.which("openssl")
        if openssl is None:
            self.skipTest("no openssl binary on PATH")
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers)
        env = bundle["dsseEnvelope"]
        payload = base64.b64decode(env["payload"])
        sig = base64.b64decode(env["signatures"][0]["sig"])
        ptype = env["payloadType"].encode("utf-8")
        pae = (b"DSSEv1 " + str(len(ptype)).encode("ascii") + b" "
               + ptype + b" " + str(len(payload)).encode("ascii")
               + b" " + payload)
        with tempfile.TemporaryDirectory() as tmp:
            paef = os.path.join(tmp, "pae.bin")
            sigf = os.path.join(tmp, "pae.sig")
            keyf = os.path.join(tmp, "key.pem")
            for path, data in ((paef, pae), (sigf, sig),
                               (keyf, _ed25519_spki_pem(
                                   signers[0].public_key))):
                with open(path, "wb") as fh:
                    fh.write(data)
            cmd = [openssl, "pkeyutl", "-verify", "-pubin",
                   "-inkey", keyf, "-rawin", "-in", paef,
                   "-sigfile", sigf]
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60)
            self.assertEqual(
                proc.returncode, 0,
                "openssl refused our envelope PAE bytes: %s %s"
                % (proc.stdout, proc.stderr))
            # Tampered bytes: openssl must refuse (non-zero exit).
            with open(paef, "r+b") as fh:
                data = bytearray(fh.read())
                data[10] ^= 0x01
                fh.seek(0)
                fh.write(bytes(data))
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=60)
            self.assertNotEqual(
                proc.returncode, 0,
                "openssl ACCEPTED tampered PAE bytes")

    def test_cosign_verify_blob_when_available(self):
        cosign = _cosign_binary()
        if cosign is None:
            self.skipTest(
                "no cosign binary (COSIGN_BIN env or PATH); structural "
                "gate above still ran. Boundary documented in REPORT.md.")
        signers = _signers(1)
        bundle = _sealed_bundle(signers=signers)
        env = bundle["dsseEnvelope"]
        payload = base64.b64decode(env["payload"])
        sig = base64.b64decode(env["signatures"][0]["sig"])
        with tempfile.TemporaryDirectory() as tmp:
            blob = os.path.join(tmp, "payload.bin")
            sigf = os.path.join(tmp, "payload.sig")
            keyf = os.path.join(tmp, "key.pem")
            for path, data in ((blob, payload), (sigf, sig),
                               (keyf, _ed25519_spki_pem(
                                   signers[0].public_key))):
                with open(path, "wb") as fh:
                    fh.write(data)
            cmd = [cosign, "verify-blob", "--key", keyf,
                   "--signature", sigf, blob]
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=45,
                    stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                self.skipTest(
                    "cosign verify-blob did not complete in 45s in this "
                    "sandbox (its startup TUF init stalls behind the "
                    "egress proxy); structural + openssl gates above "
                    "still ran. Boundary documented in REPORT.md.")
            # Happy path: cosign's real verification over our bytes.
            self.assertEqual(
                proc.returncode, 0,
                "cosign verify-blob refused our envelope bytes: %s %s"
                % (proc.stdout, proc.stderr))
            # Tampered bytes: cosign must refuse (non-zero exit).
            with open(blob, "r+b") as fh:
                data = bytearray(fh.read())
                data[10] ^= 0x01
                fh.seek(0)
                fh.write(bytes(data))
            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=45,
                    stdin=subprocess.DEVNULL)
            except subprocess.TimeoutExpired:
                self.skipTest(
                    "cosign verify-blob timed out on the tamper probe; "
                    "happy path above already ran for real.")
            self.assertNotEqual(
                proc.returncode, 0,
                "cosign verify-blob ACCEPTED tampered bytes")


class TestWitnessLogPath(unittest.TestCase):
    """Wave-312: the log-backed witness path in seal/open.

    seal_sigstore_bundle(..., witness_log=...) appends the entry's
    canonical body to a real gov.witness_log.WitnessLog: logIndex is
    the true tree position and inclusionProof carries a signed
    checkpoint + Merkle audit path. open_sigstore_bundle verifies the
    proof checkpoint-first when present; the offline fallback (no log)
    verifies exactly as before.
    """

    def test_log_backed_seal_open(self):
        from gov import evidence_sigstore, witness_log
        signers = _signers(1)
        witness = _witness()
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        wlog = witness_log.WitnessLog(witness.public_key)
        b0 = evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        b1 = evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        e0 = b0["verificationMaterial"]["tlogEntries"][0]
        e1 = b1["verificationMaterial"]["tlogEntries"][0]
        self.assertEqual(e0["logIndex"], "0")
        self.assertEqual(e1["logIndex"], "1")
        for e, want_size in ((e0, 1), (e1, 2)):
            self.assertIn("inclusionProof", e)
            cp = e["inclusionProof"]["checkpoint"]
            self.assertEqual(cp["treeSize"], want_size)
            self.assertEqual(
                cp["logId"],
                hashlib.sha256(witness.public_key).hexdigest())
        got = evidence_sigstore.open_sigstore_bundle(
            b1, BUNDLE, _verifiers(signers),
            _witness_verifier(witness), witness_validity=VALIDITY)
        self.assertTrue(got["witness"]["log_backed"])
        self.assertEqual(got["witness"]["tree_size"], 2)

    def test_fallback_still_verifies(self):
        from gov import evidence_sigstore
        bundle = _sealed_bundle()
        entry = bundle["verificationMaterial"]["tlogEntries"][0]
        self.assertNotIn("inclusionProof", entry)
        self.assertEqual(entry["logIndex"], "0")
        got = _open(bundle)
        self.assertFalse(got["witness"]["log_backed"])

    def test_tampered_audit_path_refuses_coded(self):
        from gov import evidence_sigstore
        signers = _signers(1)
        witness = _witness()
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        from gov import witness_log
        wlog = witness_log.WitnessLog(witness.public_key)
        evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        bundle = evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        bundle = copy.deepcopy(bundle)
        path = (bundle["verificationMaterial"]["tlogEntries"][0]
                ["inclusionProof"]["auditPath"])
        h = bytearray(bytes.fromhex(path[0]["hash"]))
        h[0] ^= 1
        path[0]["hash"] = bytes(h).hex()
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_sigstore.open_sigstore_bundle(
                bundle, BUNDLE, _verifiers(signers),
                _witness_verifier(witness), witness_validity=VALIDITY)
        self.assertEqual(
            _reason(ctx.exception),
            "evidence-bundle-witness-inclusion-invalid")

    def test_tampered_checkpoint_signature_refuses_coded(self):
        from gov import evidence_sigstore
        from gov import witness_log
        signers = _signers(1)
        witness = _witness()
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        wlog = witness_log.WitnessLog(witness.public_key)
        bundle = evidence_sigstore.seal_sigstore_bundle(
            env, signers, witness, witness_log=wlog,
            integrated_time=T0)
        bundle = copy.deepcopy(bundle)
        ip = bundle["verificationMaterial"]["tlogEntries"][0][
            "inclusionProof"]
        sig = bytearray(base64.b64decode(ip["checkpointSignature"]))
        sig[0] ^= 1
        ip["checkpointSignature"] = base64.b64encode(
            bytes(sig)).decode("ascii")
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_sigstore.open_sigstore_bundle(
                bundle, BUNDLE, _verifiers(signers),
                _witness_verifier(witness), witness_validity=VALIDITY)
        self.assertEqual(
            _reason(ctx.exception),
            "evidence-bundle-witness-checkpoint-invalid")

    def test_wrong_type_witness_log_refuses(self):
        from gov import evidence_sigstore
        signers = _signers(1)
        witness = _witness()
        stmt = evidence_intoto.build_statement(BUNDLE, CLAIMS)
        env = evidence_intoto.seal_statement(stmt, signers)
        with self.assertRaises(_dsse.EnvelopeError) as ctx:
            evidence_sigstore.seal_sigstore_bundle(
                env, signers, witness, witness_log="not-a-log",
                integrated_time=T0)
        self.assertEqual(_reason(ctx.exception),
                         "evidence-bundle-malformed")


if __name__ == "__main__":
    unittest.main()


