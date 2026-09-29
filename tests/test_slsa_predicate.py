#!/usr/bin/env python3
"""Unit tests for gov.slsa_predicate (wave-210 lane C).

Covers the strict in-toto Statement/v1 parse, predicate dispatch,
builder allowlist + key binding, material/subject translation, and the
fail-closed taxonomy. Red-team behavior lives in
evals/slsa_predicate_probes.py.
"""

import json
import os
import sys
import unittest

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                ".."))

from gov import build_provenance as bp  # noqa: E402
from gov import dsse_envelope as de  # noqa: E402
from gov import provenance_verifier as pv  # noqa: E402
from gov import slsa_predicate as slsa  # noqa: E402
from gov.signing import Ed25519Signer, Ed25519Verifier  # noqa: E402

_BUILDER_ID = "https://builder.example.com/ci@v1"
_BUILD_TYPE = "https://example.com/build-type@v1"
_CLOCK = 1700000000


def _signers():
    b = Ed25519Signer(bytes([21]) * 32)
    i = Ed25519Signer(bytes([22]) * 32)
    o = Ed25519Signer(bytes([23]) * 32)
    return (b, Ed25519Verifier(b.public_key, b.key_id),
            i, Ed25519Verifier(i.public_key, i.key_id),
            o, Ed25519Verifier(o.public_key, o.key_id))


def _doc(**kw):
    subjects = kw.get("subjects", (("app.tar.gz", "aa" * 32),))
    materials = kw.get("materials",
                       (("https://example.com/src@main", "bb" * 32),))
    doc = {
        "_type": kw.get("_type", slsa.STATEMENT_V1),
        "subject": [{"name": n, "digest": {"sha256": d}}
                    for n, d in subjects],
        "predicateType": kw.get("predicate_type",
                                slsa.SLSA_PROVENANCE_V1),
        "predicate": {
            "buildDefinition": {
                "buildType": _BUILD_TYPE,
                "resolvedDependencies": [
                    {"uri": u, "digest": {"sha256": d}}
                    for u, d in materials],
            },
            "runDetails": {
                "builder": {"id": kw.get("builder_id", _BUILDER_ID)},
                "metadata": {"invocationId": "build-1"},
            },
        },
    }
    return doc


def _payload_bytes(doc):
    return json.dumps(doc, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _envelope(doc, signer, payload_type=slsa.INTOTO_PAYLOAD_TYPE):
    return de.seal(_payload_bytes(doc), payload_type, [signer])


def _args(envelope, bsigner, isigner, verifiers=None, builders=None):
    b, bver, i, iver, o, over = _signers()
    return {
        "envelope": envelope,
        "verifiers": ([bver, iver, over] if verifiers is None
                      else verifiers),
        "authorized_builders": ({_BUILDER_ID: b.key_id} if builders is None
                                 else builders),
        "ingestor_signer": i if isigner is None else isigner,
        "built_at": _CLOCK,
    }


class ParseStatementTests(unittest.TestCase):
    def test_valid_doc_roundtrip(self):
        doc = _doc()
        out = slsa.parse_statement_payload(_payload_bytes(doc))
        self.assertEqual(out["predicate"]["runDetails"]["builder"]["id"],
                         _BUILDER_ID)

    def test_non_bytes_refused(self):
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload("not-bytes")

    def test_bad_json_refused(self):
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(b"{nope")

    def test_duplicate_top_level_key_refused(self):
        raw = (b'{"_type": "https://in-toto.io/Statement/v1", '
               b'"_type": "https://in-toto.io/Statement/v2", '
               b'"subject": [], "predicateType": "x", "predicate": {}}')
        with self.assertRaises(slsa.SlsaPredicateError) as ctx:
            slsa.parse_statement_payload(raw)
        self.assertIn("duplicate key", str(ctx.exception))

    def test_duplicate_nested_key_refused(self):
        doc = _doc()
        raw = json.dumps(doc, sort_keys=True,
                         separators=(",", ":")).encode("utf-8")
        # Inject a duplicate "uri" key into the first material object.
        raw = raw.replace(b'"uri":"https://example.com/src@main"',
                          b'"uri":"https://example.com/src@main",'
                          b'"uri":"https://example.com/evil"')
        with self.assertRaises(slsa.SlsaPredicateError) as ctx:
            slsa.parse_statement_payload(raw)
        self.assertIn("duplicate key", str(ctx.exception))

    def test_non_object_refused(self):
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(b"[1,2]")

    def test_unknown_top_field_refused(self):
        doc = _doc()
        doc["evil"] = 1
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_v2_explicitly_unsupported(self):
        doc = _doc(_type=slsa.STATEMENT_V2)
        with self.assertRaises(slsa.SlsaPredicateError) as ctx:
            slsa.parse_statement_payload(_payload_bytes(doc))
        self.assertIn("UNPUBLISHED", str(ctx.exception))

    def test_unknown_type_refused(self):
        doc = _doc(_type="https://in-toto.io/Statement/v9")
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_unknown_predicate_refused(self):
        doc = _doc(predicate_type="https://slsa.dev/provenance/v0.2")
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_empty_subject_refused(self):
        doc = _doc(subjects=())
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_duplicate_subject_names_refused(self):
        doc = _doc(subjects=(("a", "aa" * 32), ("a", "bb" * 32)))
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_non_hex_subject_digest_refused(self):
        doc = _doc(subjects=(("a", "zz" * 32),))
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_empty_materials_refused(self):
        doc = _doc(materials=())
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_duplicate_material_uri_refused(self):
        doc = _doc(materials=(("u", "aa" * 32), ("u", "bb" * 32)))
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_missing_material_digest_refused(self):
        doc = _doc()
        del doc["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"]
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_digest_without_sha256_refused(self):
        doc = _doc()
        doc["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"] = {"sha512": "ab" * 64}
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_extra_digest_algorithm_tolerated(self):
        doc = _doc()
        doc["subject"][0]["digest"]["sha512"] = "ab" * 64
        out = slsa.parse_statement_payload(_payload_bytes(doc))
        self.assertEqual(out["subject"][0]["digest"]["sha256"],
                         "aa" * 32)

    def test_missing_builder_id_refused(self):
        doc = _doc()
        doc["predicate"]["runDetails"]["builder"] = {}
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_external_parameters_nondict_refused(self):
        doc = _doc()
        doc["predicate"]["buildDefinition"]["externalParameters"] = [1]
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_metadata_nondict_refused(self):
        doc = _doc()
        doc["predicate"]["runDetails"]["metadata"] = "x"
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))

    def test_unknown_predicate_field_refused(self):
        doc = _doc()
        doc["predicate"]["runDetails"]["builder"]["extra"] = 1
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.parse_statement_payload(_payload_bytes(doc))


class IngestTests(unittest.TestCase):
    def test_valid_ingest_report(self):
        bsigner, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        ing = slsa.ingest(**_args(env, bsigner, isigner,
                                 verifiers=[bver, iver]))
        rep = ing.to_report()
        self.assertEqual(rep["builder_id"], _BUILDER_ID)
        self.assertEqual(rep["build_type"], _BUILD_TYPE)
        self.assertEqual(rep["ingestor_key_id"], isigner.key_id)
        self.assertEqual(rep["built_at"], _CLOCK)
        self.assertEqual(rep["subjects"], {"app.tar.gz": "aa" * 32})
        self.assertEqual(rep["materials"],
                         [("https://example.com/src@main", "bb" * 32)])
        self.assertEqual(len(rep["predicate_sha256"]), 64)
        self.assertEqual(len(rep["envelope_sha256"]), 64)
        # Recipe digest-pinned by construction.
        stmt = ing.sealed["app.tar.gz"]["statement"]
        self.assertTrue(
            stmt["recipe"].startswith("slsa-provenance/v1@sha256:"))
        self.assertEqual(stmt["builder"], _BUILDER_ID)
        # Sealed by the ingestor key, not the builder key.
        self.assertEqual(ing.sealed["app.tar.gz"]["key_id"],
                         isigner.key_id)
        # Inputs are digest-pinned and non-deterministic (evidence).
        self.assertEqual(stmt["inputs"][0]["digest"], "bb" * 32)
        self.assertFalse(stmt["inputs"][0]["deterministic"])

    def test_sealed_statements_verify_with_ingestor_key(self):
        bsigner, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        ing = slsa.ingest(**_args(env, bsigner, isigner,
                                 verifiers=[bver, iver]))
        stmt = bp.verify_sealed_statement(ing.sealed["app.tar.gz"],
                                         "aa" * 32, iver)
        self.assertEqual(stmt.artifact_hex, "aa" * 32)

    def test_chain_inputs_shape(self):
        bsigner, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        ing = slsa.ingest(**_args(env, bsigner, isigner,
                                 verifiers=[bver, iver]))
        named, artifacts = slsa.chain_inputs(ing)
        self.assertEqual(set(named), {"app.tar.gz"})
        self.assertEqual(artifacts, {"app.tar.gz": "aa" * 32})
        out = pv.verify_provenance_chain(
            named, artifacts,
            [("REQUIRE", "app.tar.gz"), ("DISALLOW",)],
            {iver.key_id: iver})
        self.assertEqual(out["consumed"], ["app.tar.gz"])

    def test_chain_inputs_wrong_type_refused(self):
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.chain_inputs({"not": "ingestion"})

    def test_empty_verifiers_refused(self):
        bsigner, _, isigner, _, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.ingest(**_args(env, bsigner, isigner, verifiers=[]))

    def test_empty_allowlist_refused(self):
        bsigner, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.ingest(**_args(env, bsigner, isigner, builders={}))

    def test_ingestor_not_signer_refused(self):
        bsigner, bver, _, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        args = _args(env, bsigner, None)
        args["ingestor_signer"] = iver  # a Verifier, not a Signer
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.ingest(**args)

    def test_bad_built_at_refused(self):
        bsigner, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        args = _args(env, bsigner, isigner)
        args["built_at"] = -1
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.ingest(**args)

    def test_no_verifier_for_bound_key_refused(self):
        bsigner, _, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner)
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.ingest(**_args(env, bsigner, isigner, verifiers=[iver]))

    def test_wrong_payload_type_refused(self):
        bsigner, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), bsigner,
                        payload_type="application/json")
        with self.assertRaises(slsa.SlsaPredicateError) as ctx:
            slsa.ingest(**_args(env, bsigner, isigner,
                               verifiers=[bver, iver]))
        self.assertIn("payloadType", str(ctx.exception))

    def test_unsigned_envelope_refused(self):
        _, bver, isigner, iver, _, _ = _signers()
        env = _envelope(_doc(), Ed25519Signer(bytes([99]) * 32))
        with self.assertRaises(slsa.SlsaPredicateError):
            slsa.ingest(**_args(env, None, isigner,
                               verifiers=[bver, iver]))

    def test_unauthorized_builder_refused(self):
        evil = Ed25519Signer(bytes([98]) * 32)
        bsigner, _, isigner, _, _, _ = _signers()
        env = _envelope(_doc(builder_id="https://evil.example.com/x"),
                        evil)
        with self.assertRaises(slsa.SlsaPredicateError) as ctx:
            slsa.ingest(**_args(env, bsigner, isigner))
        self.assertIn("allowlist", str(ctx.exception))

    def test_wrong_key_for_builder_refused(self):
        bsigner, bver, isigner, iver, osigner, over = _signers()
        env = _envelope(_doc(), osigner)
        with self.assertRaises(slsa.SlsaPredicateError) as ctx:
            slsa.ingest(**_args(env, bsigner, isigner,
                               verifiers=[bver, iver, over]))
        self.assertIn("signature", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
