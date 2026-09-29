#!/usr/bin/env python3
"""Wave-210 lane C red-team probes: SLSA predicate adapter.

Break-first battery per the diagnosing-bugs skill. Pattern lineage:
the in-toto Attestation Framework's envelope layering (envelope
validation -> predicate dispatch -> artifact-rule checks) and SLSA
v1.2's ``provenance/v1`` predicate shape -- re-implemented stdlib-only,
nothing vendored.

The pristine tree has the provenance RECORD (gov.build_provenance),
the artifact-rule VERIFIER (gov.provenance_verifier) and the DSSE
envelope (gov.dsse_envelope), but NO SLSA predicate adapter:
gov.slsa_predicate is absent. Each probe attacks that gap:

  S1  VALID_INGEST_AND_CHAIN  valid SLSA v1 statement, authorized
                              builder, builder-bound key -> ingests;
                              translated statements feed
                              verify_provenance_chain UNCHANGED
                              (REQUIRE + MATCH + terminal DISALLOW)
  S2  V2_TYPE_REFUSED         _type = Statement/v2 (policy-defined but
                              UNPUBLISHED) -> explicit unsupported-
                              version refusal, never best-effort parse
  S3  UNKNOWN_TYPE_REFUSED    unknown _type / unknown predicateType ->
                              refused
  S4  MATERIAL_MISMATCH       material digest tampered post-signing ->
                              signature-path refusal; ingested chain
                              with a wrong MATCH digest -> chain refusal
  S5  UNAUTHORIZED_BUILDER    builder.id outside the allowlist, valid
                              signature -> refused (a valid signature
                              from an unknown builder is not a pass)
  S6  MISSING_MATERIAL_DIGEST material without a digest / without
                              sha256 -> refused
  S7  WRONG_KEY_FOR_BUILDER   envelope signed by a trusted key that is
                              NOT bound to the claimed builder.id ->
                              refused (the cosign rule: bind digest +
                              expected identity + issuer)
  S8  FIELD_CONFUSION         buildDefinition/runDetails swapped ->
                              refused, not coerced
  S9  SUBJECT_TAMPER          subject digest tampered post-signing ->
                              refused on the signature path

On the pristine tree every probe reports GAP (module absent -- genuine
red). After the fix all must flip to HELD.

Verdicts: HELD (defense held), GAP (gap demonstrated -- the red
phase), ERROR only on harness failure (a verdict changing between the
two deterministic runs, an unexpected exception).

Deterministic: fixed seeds for Ed25519 signers, fixed clock; every
probe runs twice and a verdict change is an ERROR. Synthetic/local
only. ``GOV_SKIP_GREEN=1`` is honored (green check records a skip
instead of spawning sub-batteries).
"""

import base64 as _b64
import json as _json
import os
import sys

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

REPO = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, REPO)

_SKIP_GREEN = os.environ.get("GOV_SKIP_GREEN") == "1"

try:
    from gov import build_provenance as _bp
    from gov import dsse_envelope as _de
    from gov import provenance_verifier as _pv
    from gov import slsa_predicate as _slsa
    from gov.signing import Ed25519Signer, Ed25519Verifier
    _ABSENT = False
except ImportError:
    _ABSENT = True

_RESULTS = []
_FIXED_CLOCK = 1700000000
_BUILDER_ID = "https://builder.example.com/ci@v1"
_BUILD_TYPE = "https://example.com/build-type@v1"


def _record(probe_id, name, verdict, detail):
    _RESULTS.append({"id": probe_id, "name": name, "verdict": verdict,
                     "detail": detail})


def _gap(probe_id, name, detail):
    _record(probe_id, name, "GAP", detail)


def _held(probe_id, name, detail):
    _record(probe_id, name, "HELD", detail)


def _run_twice(fn):
    """Run a probe twice; a verdict change between runs is an ERROR."""
    first = fn()
    second = fn()
    if first[0] != second[0]:
        return ("ERROR",
                "nondeterministic verdict: %r vs %r" % (first, second))
    return first


def _expect_refusal(fn, must_mention=None):
    try:
        fn()
    except _slsa.SlsaPredicateError as exc:
        if must_mention and must_mention not in str(exc):
            return ("ERROR", "refusal message missing %r: %s"
                    % (must_mention, exc))
        return ("HELD", "refused: %s" % exc)
    except Exception as exc:  # noqa: BLE001 - taxonomy check
        return ("ERROR", "wrong exception taxonomy: %r: %s"
                % (type(exc).__name__, exc))
    return ("GAP", "not refused")


def _keys():
    b = Ed25519Signer(bytes([11]) * 32)  # builder key
    i = Ed25519Signer(bytes([12]) * 32)  # ingestor key
    o = Ed25519Signer(bytes([13]) * 32)  # other trusted key
    return (b, Ed25519Verifier(b.public_key, b.key_id),
            i, Ed25519Verifier(i.public_key, i.key_id),
            o, Ed25519Verifier(o.public_key, o.key_id))


def _statement_doc(builder_id=_BUILDER_ID, build_type=_BUILD_TYPE,
                   subjects=(("app.tar.gz", "aa" * 32),),
                   materials=(("https://example.com/src@main",
                               "bb" * 32),),
                   _type=None, predicate_type=None, predicate=None):
    doc = {
        "_type": _type or _slsa.STATEMENT_V1,
        "subject": [{"name": name,
                     "digest": {"sha256": digest}}
                    for name, digest in subjects],
        "predicateType": (predicate_type or _slsa.SLSA_PROVENANCE_V1),
        "predicate": predicate if predicate is not None else {
            "buildDefinition": {
                "buildType": build_type,
                "resolvedDependencies": [
                    {"uri": uri, "digest": {"sha256": digest}}
                    for uri, digest in materials],
            },
            "runDetails": {
                "builder": {"id": builder_id},
                "metadata": {"invocationId": "build-1"},
            },
        },
    }
    return doc


def _envelope(doc, signer):
    payload = _json.dumps(doc, sort_keys=True,
                          separators=(",", ":")).encode("utf-8")
    return _de.seal(payload, _slsa.INTOTO_PAYLOAD_TYPE, [signer])


def _ingest_args(envelope, bsigner, isigner, builder_id=_BUILDER_ID):
    _, bver, _, iver, _, over = _keys()
    return {
        "envelope": envelope,
        "verifiers": [bver, iver, over],
        "authorized_builders": {builder_id: bsigner.key_id},
        "ingestor_signer": isigner,
        "built_at": _FIXED_CLOCK,
    }


def probe_s1_valid_ingest_and_chain():
    def one():
        bsigner, _, isigner, iver, _, _ = _keys()
        doc = _statement_doc(
            subjects=(("app.tar.gz", "aa" * 32), ("lib.o", "cc" * 32)),
            materials=(("https://example.com/src@main", "bb" * 32),
                       ("https://example.com/dep@v2", "dd" * 32)))
        env = _envelope(doc, bsigner)
        try:
            ing = _slsa.ingest(**_ingest_args(env, bsigner, isigner))
        except _slsa.SlsaPredicateError as exc:
            return ("ERROR", "valid ingestion refused: %s" % exc)
        rep = ing.to_report()
        if rep["builder_id"] != _BUILDER_ID:
            return ("ERROR", "builder_id mistranslated: %r" % rep)
        if rep["ingestor_key_id"] != isigner.key_id:
            return ("ERROR", "ingestor key not recorded: %r" % rep)
        if len(rep["materials"]) != 2:
            return ("ERROR", "materials mistranslated: %r" % rep)
        # The recipe must be digest-pinned by construction.
        stmt_doc = ing.sealed["app.tar.gz"]["statement"]
        if not stmt_doc["recipe"].startswith("slsa-provenance/v1@sha256:"):
            return ("ERROR", "recipe not digest-pinned: %r"
                    % stmt_doc["recipe"])
        # Existing checks run UNCHANGED: REQUIRE + MATCH + DISALLOW.
        named, artifacts = ing.chain_inputs()
        try:
            out = _pv.verify_provenance_chain(
                named, artifacts,
                [("REQUIRE", "app.tar.gz"),
                 ("MATCH", "lib.o", "cc" * 32),
                 ("DISALLOW",)],
                {iver.key_id: iver})
        except _pv.ProvenanceVerifierError as exc:
            return ("ERROR", "chain refused after valid ingest: %s" % exc)
        if out["consumed"] != ["app.tar.gz", "lib.o"]:
            return ("ERROR", "chain consumed wrong set: %r" % out)
        return ("HELD", "valid SLSA v1 ingests; native chain unchanged")
    return _run_twice(one)


def probe_s2_v2_type_refused():
    def one():
        bsigner, _, isigner, _, _, _ = _keys()
        doc = _statement_doc(_type=_slsa.STATEMENT_V2)
        env = _envelope(doc, bsigner)
        return _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)),
            must_mention="UNPUBLISHED")
    return _run_twice(one)


def probe_s3_unknown_type_refused():
    def one():
        bsigner, _, isigner, _, _, _ = _keys()
        doc = _statement_doc(_type="https://in-toto.io/Statement/v9")
        env = _envelope(doc, bsigner)
        r1 = _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)),
            must_mention="unsupported statement _type")
        if r1[0] != "HELD":
            return r1
        doc2 = _statement_doc(
            predicate_type="https://slsa.dev/provenance/v0.2")
        env2 = _envelope(doc2, bsigner)
        r2 = _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env2, bsigner, isigner)),
            must_mention="unsupported predicateType")
        return r2
    return _run_twice(one)


def probe_s4_material_mismatch():
    def one():
        bsigner, _, isigner, iver, _, _ = _keys()
        # (i) material digest tampered AFTER signing -> signature path.
        doc = _statement_doc()
        env = _envelope(doc, bsigner)
        payload = _json.loads(_b64.b64decode(
            env["payload"]).decode("utf-8"))
        payload["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"]["sha256"] = "ff" * 32
        env["payload"] = _b64.b64encode(
            _json.dumps(payload, sort_keys=True,
                        separators=(",", ":")).encode("utf-8")).decode()
        r1 = _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)),
            must_mention="signature")
        if r1[0] != "HELD":
            return r1
        # (ii) chain-level: ingested materials bind MATCH digests.
        doc2 = _statement_doc()
        env2 = _envelope(doc2, bsigner)
        ing = _slsa.ingest(**_ingest_args(env2, bsigner, isigner))
        named, artifacts = ing.chain_inputs()
        try:
            _pv.verify_provenance_chain(
                named, artifacts,
                [("MATCH", "app.tar.gz", "00" * 32), ("DISALLOW",)],
                {iver.key_id: iver})
        except _pv.ProvenanceVerifierError:
            return ("HELD", "tampered material refused on signature path; "
                            "wrong subject digest refused at chain via MATCH")
        return ("GAP", "wrong MATCH digest not refused")
    return _run_twice(one)


def probe_s5_unauthorized_builder():
    def one():
        evil = Ed25519Signer(bytes([14]) * 32)
        bsigner, _, isigner, _, _, _ = _keys()
        doc = _statement_doc(builder_id="https://evil.example.com/x")
        env = _envelope(doc, evil)
        # evil's signature is valid, but evil is not in the allowlist.
        return _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)),
            must_mention="allowlist")
    return _run_twice(one)


def probe_s6_missing_material_digest():
    def one():
        bsigner, _, isigner, _, _, _ = _keys()
        doc = _statement_doc()
        del doc["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"]
        env = _envelope(doc, bsigner)
        r1 = _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)),
            must_mention="digest")
        if r1[0] != "HELD":
            return r1
        doc2 = _statement_doc()
        doc2["predicate"]["buildDefinition"]["resolvedDependencies"][0][
            "digest"] = {"sha512": "ab" * 64}  # no sha256
        env2 = _envelope(doc2, bsigner)
        return _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env2, bsigner, isigner)),
            must_mention="sha256")
    return _run_twice(one)


def probe_s7_wrong_key_for_builder():
    def one():
        bsigner, _, isigner, _, osigner, over = _keys()
        doc = _statement_doc()  # claims the authorized builder id
        env = _envelope(doc, osigner)  # but signed by the OTHER key
        _, bver, _, iver, _, _ = _keys()
        args = _ingest_args(env, bsigner, isigner)
        args["verifiers"] = [bver, iver, over]
        return _expect_refusal(lambda: _slsa.ingest(**args),
                               must_mention="signature")
    return _run_twice(one)


def probe_s8_field_confusion():
    def one():
        bsigner, _, isigner, _, _, _ = _keys()
        doc = _statement_doc()
        pred = doc["predicate"]
        # Swap the two sections: buildDefinition-shaped runDetails and
        # vice versa. A coercing parser would accept this.
        doc["predicate"] = {"buildDefinition": pred["runDetails"],
                            "runDetails": pred["buildDefinition"]}
        env = _envelope(doc, bsigner)
        return _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)))
    return _run_twice(one)


def probe_s9_subject_tamper():
    def one():
        bsigner, _, isigner, _, _, _ = _keys()
        doc = _statement_doc()
        env = _envelope(doc, bsigner)
        payload = _json.loads(_b64.b64decode(env["payload"]).decode("utf-8"))
        payload["subject"][0]["digest"]["sha256"] = "ee" * 32
        env["payload"] = _b64.b64encode(
            _json.dumps(payload, sort_keys=True,
                        separators=(",", ":")).encode("utf-8")).decode()
        return _expect_refusal(
            lambda: _slsa.ingest(**_ingest_args(env, bsigner, isigner)),
            must_mention="signature")
    return _run_twice(one)


_PROBES = [
    ("S1", "VALID_INGEST_AND_CHAIN", probe_s1_valid_ingest_and_chain),
    ("S2", "V2_TYPE_REFUSED", probe_s2_v2_type_refused),
    ("S3", "UNKNOWN_TYPE_REFUSED", probe_s3_unknown_type_refused),
    ("S4", "MATERIAL_MISMATCH", probe_s4_material_mismatch),
    ("S5", "UNAUTHORIZED_BUILDER", probe_s5_unauthorized_builder),
    ("S6", "MISSING_MATERIAL_DIGEST", probe_s6_missing_material_digest),
    ("S7", "WRONG_KEY_FOR_BUILDER", probe_s7_wrong_key_for_builder),
    ("S8", "FIELD_CONFUSION", probe_s8_field_confusion),
    ("S9", "SUBJECT_TAMPER", probe_s9_subject_tamper),
]


def main():
    if _ABSENT:
        for pid, name, _ in _PROBES:
            _gap(pid, name, "gov.slsa_predicate absent")
    else:
        for pid, name, fn in _PROBES:
            verdict, detail = fn()
            _record(pid, name, verdict, detail)
    held = sum(1 for r in _RESULTS if r["verdict"] == "HELD")
    gaps = sum(1 for r in _RESULTS if r["verdict"] == "GAP")
    errors = sum(1 for r in _RESULTS if r["verdict"] == "ERROR")
    for r in _RESULTS:
        print("%s %-24s %s: %s" % (r["id"], r["name"], r["verdict"],
                                   r["detail"]))
    print("== %d HELD / %d GAP / %d ERROR out of %d =="
          % (held, gaps, errors, len(_RESULTS)))
    return 0 if errors == 0 else 1


def green_check():
    """Adjacent-battery green check (depth-1: children get
    GOV_SKIP_GREEN=1 so they never nest further)."""
    import subprocess
    import tempfile
    if _SKIP_GREEN:
        print("GREEN CHECK: skipped (GOV_SKIP_GREEN=1)")
        return 0
    here = os.path.dirname(os.path.abspath(__file__))
    tmpdir = tempfile.mkdtemp(prefix="g210c-green-")
    env = dict(os.environ)
    env["GOV_SKIP_GREEN"] = "1"
    env["TMPDIR"] = tmpdir
    rc = 0
    for battery in ("dsse_envelope_probes.py",
                    "provenance_envelope_probes.py"):
        try:
            proc = subprocess.run(
                [sys.executable, os.path.join(here, battery)],
                env=env, capture_output=True, text=True, timeout=600)
        except Exception as exc:  # noqa: BLE001 - green check must not crash
            print("GREEN CHECK %s: harness error: %s" % (battery, exc))
            return 1
        print("GREEN CHECK %s: exit=%d" % (battery, proc.returncode))
        rc = rc or proc.returncode
    return rc


if __name__ == "__main__":
    sys.exit(main())
