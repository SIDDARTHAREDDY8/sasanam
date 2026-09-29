"""SLSA provenance predicate adapter: ingest in-toto Statement/v1 +
SLSA ``provenance/v1`` predicates into the native artifact-rule
provenance verifier.

PATTERN LINEAGE: the in-toto Attestation Framework's envelope layering
(envelope validation -> predicate dispatch -> artifact-rule checks) and
SLSA v1.2's ``provenance/v1`` predicate shape. Re-implemented in
stdlib Python -- NO in-toto/SLSA code is vendored here, only the
pattern (field names and URI identifiers as data-model facts).

LICENSE POSTURE (verified this wave, 2026-09-29): in-toto's official
governance document (in-toto/community GOVERNANCE.md, "License"
section) states "All software is licensed under the Apache License
version 2.0, and all documentation is licensed under the Creative
Commons License version 4.0, and the specification is licensed under
the Community Specification License"; the in-toto/attestation repo
carries a root LICENSE file and third-party license indexes record
Apache-2.0 from that file (verified 2026-09-18). The SLSA
specification (slsa.dev) is under the Community Specification License
1.0. This module copies NO spec text and NO upstream code -- only
public identifier URIs and field names -- so license exposure is nil
either way.

VERSION DISCIPLINE (the wave-209 prospectus correction): the in-toto
versioning policy names a hypothetical ``Statement/v2`` ("_type
becomes https://in-toto.io/Statement/v2" under a future MAJOR), but
Statement/v2 is UNPUBLISHED. This adapter accepts ONLY
``https://in-toto.io/Statement/v1`` and fails closed on
``Statement/v2`` or any unknown ``_type`` with an explicit
unsupported-version error -- never best-effort parse.

Pipeline::

    DSSE envelope validation (payloadType pinned to
    ``application/vnd.in-toto+json``)
      -> in-toto Statement/v1 strict parse (exact field allowlist)
      -> predicate dispatch: ONLY ``https://slsa.dev/provenance/v1``
         (unknown predicate types refused, never coerced)
      -> DSSE signature verification against the key BOUND to the
         claimed ``builder.id`` (authorized-builder allowlist; a valid
         signature from the WRONG builder is a refusal, not a pass --
         the cosign rule: bind digest + expected identity + issuer)
      -> field translation into native ``ProvenanceStatement``
         records: builder.id -> builder; the canonical buildDefinition
         digest -> digest-pinned recipe ref; resolvedDependencies ->
         digest-pinned inputs (materials WITHOUT a sha256 digest are
         refused); subject -> artifact binding
      -> re-seal with the deployment's INGESTION key; the caller feeds
         the sealed statements into
         ``gov.provenance_verifier.verify_provenance_chain`` UNCHANGED.

The re-seal is labeled honestly: the sealed statements record
``builder.id`` as the builder and the ingestion report retains the
original envelope digest, so an auditor can always re-open the SLSA
envelope itself. The ingestion key vouches "this deployment verified
this SLSA statement against its builder allowlist" -- it does NOT
upgrade the builder's claim.

Materials are translated with ``deterministic=False`` (evidence, not
promises): a SLSA material is a resolved dependency digest, not a
re-derivable input, so the double-build discipline reports them as
unchecked rather than pretending to re-derive them.

NARROW CLAIM (six-source consensus, carried here too): SLSA
provenance is evidence of BUILD INTEGRITY (this builder, these
materials) -- never artifact safety. A verified ingestion says who
could have lied about the build, not that the artifact is benign.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json

from . import build_provenance as _bp
from . import dsse_envelope as _de
from .signing import Signer, Verifier

__all__ = [
    "INTOTO_PAYLOAD_TYPE",
    "SLSA_PROVENANCE_V1",
    "STATEMENT_V1",
    "STATEMENT_V2",
    "SlsaIngestion",
    "SlsaPredicateError",
    "chain_inputs",
    "ingest",
    "parse_statement_payload",
]

STATEMENT_V1 = "https://in-toto.io/Statement/v1"
STATEMENT_V2 = "https://in-toto.io/Statement/v2"
SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1"
INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_STATEMENT_FIELDS = frozenset({"_type", "subject", "predicateType",
                               "predicate"})
_SUBJECT_FIELDS = frozenset({"name", "digest", "uri"})
_PREDICATE_FIELDS = frozenset({"buildDefinition", "runDetails"})
_BUILD_DEF_FIELDS = frozenset({"buildType", "resolvedDependencies",
                               "externalParameters"})
_MATERIAL_FIELDS = frozenset({"uri", "digest", "name"})
_RUN_DETAILS_FIELDS = frozenset({"builder", "metadata", "byproducts"})
_BUILDER_FIELDS = frozenset({"id"})


class SlsaPredicateError(ValueError):
    """Raised loudly on any SLSA predicate ingestion failure."""


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise SlsaPredicateError("%s: digest must be str, got %s"
                                 % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise SlsaPredicateError("%s: not a sha256 hex digest: %r"
                                 % (where, value))
    return value


def _strict_doc(doc, allowed, where):
    if not isinstance(doc, dict):
        raise SlsaPredicateError("%s: must be a dict, got %s"
                                 % (where, type(doc).__name__))
    extra = set(doc) - allowed
    if extra:
        raise SlsaPredicateError("%s: unknown field(s) refused: %s"
                                 % (where, sorted(extra)))
    return doc


def _digest_map(doc, where):
    """A SLSA digest map: sha256 REQUIRED (our identity algorithm);
    other algorithms are tolerated but never used for identity (the
    spec's digest map is multi-algorithm by design)."""
    if not isinstance(doc, dict):
        raise SlsaPredicateError("%s: digest must be a dict, got %s"
                                 % (where, type(doc).__name__))
    if "sha256" not in doc:
        raise SlsaPredicateError("%s: digest map has no sha256 entry "
                                 "(refused: sha256 is our identity "
                                 "algorithm)" % where)
    return _check_hex_digest(doc["sha256"], where + ".sha256")


def _strict_loads(payload_bytes):
    """JSON-decode with duplicate object keys refused.

    ``json.loads`` silently collapses duplicate keys (last-wins), so the
    parsed view can differ from the signed bytes under duplicate keys.
    A strict fail-closed parser refuses them: only the authorized
    builder can produce signed bytes, but last-wins coercion is not a
    check we want to depend on.
    """
    if not isinstance(payload_bytes, (bytes, bytearray)):
        raise SlsaPredicateError("payload must be bytes, got %s"
                                 % type(payload_bytes).__name__)
    try:
        text = bytes(payload_bytes).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SlsaPredicateError("payload is not valid UTF-8: %s" % exc)

    def _no_dup_object(pairs):
        obj = {}
        for key, value in pairs:
            if key in obj:
                raise SlsaPredicateError(
                    "payload has duplicate key %r (refused: strict "
                    "parse)" % key)
            obj[key] = value
        return obj

    try:
        return json.loads(text, object_pairs_hook=_no_dup_object)
    except SlsaPredicateError:
        raise
    except ValueError as exc:
        raise SlsaPredicateError("payload is not valid JSON: %s" % exc)


def parse_statement_payload(payload_bytes):
    """Strict-parse an in-toto statement payload (bytes).

    Returns the parsed dict. Refuses: non-JSON, non-object,
    duplicate JSON object keys, unknown top-level fields, any ``_type``
    other than Statement/v1 (v2 gets an explicit unsupported-version
    error), any ``predicateType`` other than SLSA provenance/v1,
    malformed subjects/materials/builder.
    """
    doc = _strict_loads(payload_bytes)
    _strict_doc(doc, _STATEMENT_FIELDS, "statement")
    got_type = doc.get("_type")
    if got_type == STATEMENT_V2:
        raise SlsaPredicateError(
            "unsupported statement version %r: Statement/v2 is "
            "policy-defined but UNPUBLISHED; refusing (never "
            "best-effort parse)" % got_type)
    if got_type != STATEMENT_V1:
        raise SlsaPredicateError(
            "unsupported statement _type %r: only %r is accepted"
            % (got_type, STATEMENT_V1))
    if doc.get("predicateType") != SLSA_PROVENANCE_V1:
        raise SlsaPredicateError(
            "unsupported predicateType %r: only %r is accepted"
            % (doc.get("predicateType"), SLSA_PROVENANCE_V1))

    subjects = doc.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise SlsaPredicateError("subject must be a non-empty list")
    seen_names = set()
    for i, sub in enumerate(subjects):
        where = "subject[%d]" % i
        _strict_doc(sub, _SUBJECT_FIELDS, where)
        name = sub.get("name")
        if not isinstance(name, str) or not name:
            raise SlsaPredicateError(
                "%s: name must be a non-empty str (the artifact-rule "
                "verifier needs named artifacts)" % where)
        if name in seen_names:
            raise SlsaPredicateError(
                "%s: duplicate subject name %r" % (where, name))
        seen_names.add(name)
        _digest_map(sub.get("digest"), where + ".digest")
        uri = sub.get("uri")
        if uri is not None and (not isinstance(uri, str) or not uri):
            raise SlsaPredicateError(
                "%s: uri must be a non-empty str when present" % where)

    predicate = doc.get("predicate")
    _strict_doc(predicate, _PREDICATE_FIELDS, "predicate")
    build_def = predicate.get("buildDefinition")
    _strict_doc(build_def, _BUILD_DEF_FIELDS, "predicate.buildDefinition")
    build_type = build_def.get("buildType")
    if not isinstance(build_type, str) or not build_type:
        raise SlsaPredicateError("predicate.buildDefinition.buildType "
                                 "must be a non-empty str")
    materials = build_def.get("resolvedDependencies")
    if not isinstance(materials, list) or not materials:
        raise SlsaPredicateError(
            "predicate.buildDefinition.resolvedDependencies must be a "
            "non-empty list (a build with no digest-pinned materials "
            "cannot be translated)")
    seen_uris = set()
    for i, mat in enumerate(materials):
        where = "resolvedDependencies[%d]" % i
        _strict_doc(mat, _MATERIAL_FIELDS, where)
        uri = mat.get("uri")
        if not isinstance(uri, str) or not uri:
            raise SlsaPredicateError("%s: uri must be a non-empty str"
                                     % where)
        if uri in seen_uris:
            raise SlsaPredicateError(
                "%s: duplicate material uri %r" % (where, uri))
        seen_uris.add(uri)
        # Materials WITHOUT a sha256 digest are refused -- a material
        # that cannot be digest-bound cannot become a REQUIRE/MATCH
        # input.
        _digest_map(mat.get("digest"), where + ".digest")
        mname = mat.get("name")
        if mname is not None and (not isinstance(mname, str) or not mname):
            raise SlsaPredicateError(
                "%s: name must be a non-empty str when present" % where)
    ext = build_def.get("externalParameters")
    if ext is not None and not isinstance(ext, dict):
        raise SlsaPredicateError(
            "predicate.buildDefinition.externalParameters must be a "
            "dict when present")

    run_details = predicate.get("runDetails")
    _strict_doc(run_details, _RUN_DETAILS_FIELDS, "predicate.runDetails")
    builder = run_details.get("builder")
    _strict_doc(builder, _BUILDER_FIELDS, "predicate.runDetails.builder")
    builder_id = builder.get("id")
    if not isinstance(builder_id, str) or not builder_id:
        raise SlsaPredicateError("predicate.runDetails.builder.id must "
                                 "be a non-empty str")
    metadata = run_details.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        raise SlsaPredicateError("predicate.runDetails.metadata must be "
                                 "a dict when present (informational, "
                                 "never trusted)")
    byproducts = run_details.get("byproducts")
    if byproducts is not None and not isinstance(byproducts, list):
        raise SlsaPredicateError("predicate.runDetails.byproducts must "
                                 "be a list when present (informational, "
                                 "never trusted)")
    return doc


class SlsaIngestion(object):
    """The result of a verified SLSA predicate ingestion.

    ``sealed`` maps artifact name -> native sealed ProvenanceStatement
    (signed by the INGESTION key -- see module docstring for what that
    vouches). The in-band marker that these are second-hand ingested
    claims (not native build records) is the recipe prefix
    ``slsa-provenance/v1@sha256:`` -- never a native recipe scheme --
    plus the ingestor ``key_id`` on the sealed statement and the
    ``envelope_sha256`` in the report for re-opening the original.

    ``chain_inputs()`` is the ONLY supported path for feeding these
    into ``verify_provenance_chain``: it derives both named_statements
    and the artifacts receipt dict from the same signature-verified
    subject loop, so they cannot diverge. Do not hand-build the mapping
    from ``ing.sealed``/``ing.subjects`` -- mutating those attributes
    before calling ``chain_inputs()`` is outside the contract.
    """

    __slots__ = ("builder_id", "build_type", "predicate_sha256",
                 "envelope_sha256", "ingestor_key_id", "built_at",
                 "subjects", "materials", "sealed")

    def __init__(self, builder_id, build_type, predicate_sha256,
                 envelope_sha256, ingestor_key_id, built_at, subjects,
                 materials, sealed):
        self.builder_id = builder_id
        self.build_type = build_type
        self.predicate_sha256 = predicate_sha256
        self.envelope_sha256 = envelope_sha256
        self.ingestor_key_id = ingestor_key_id
        self.built_at = built_at
        self.subjects = dict(subjects)
        self.materials = list(materials)
        self.sealed = dict(sealed)

    def chain_inputs(self):
        """(named_statements, artifacts) for verify_provenance_chain."""
        return (dict(self.sealed),
                dict(self.subjects))

    def to_report(self):
        return {
            "builder_id": self.builder_id,
            "build_type": self.build_type,
            "predicate_sha256": self.predicate_sha256,
            "envelope_sha256": self.envelope_sha256,
            "ingestor_key_id": self.ingestor_key_id,
            "built_at": self.built_at,
            "subjects": dict(self.subjects),
            "materials": list(self.materials),
        }


def _strict_authorized_builders(authorized_builders):
    if not isinstance(authorized_builders, dict) or not authorized_builders:
        raise SlsaPredicateError("authorized_builders must be a non-empty "
                                 "dict of builder.id -> signing key_id")
    bound = {}
    for builder_id, key_id in authorized_builders.items():
        if not isinstance(builder_id, str) or not builder_id:
            raise SlsaPredicateError("authorized_builders: builder.id "
                                     "must be a non-empty str")
        if not isinstance(key_id, str) or not key_id:
            raise SlsaPredicateError(
                "authorized_builders[%r]: key_id must be a non-empty str"
                % builder_id)
        bound[builder_id] = key_id
    return bound


def ingest(envelope, verifiers, authorized_builders, ingestor_signer,
           built_at):
    """Verify a DSSE-wrapped SLSA provenance statement and translate it
    into native sealed provenance statements.

    ``envelope``: DSSE envelope dict whose payload is an in-toto
    Statement/v1 with SLSA ``provenance/v1`` predicate.
    ``verifiers``: non-empty list of gov.signing.Verifier; must include
    the verifier for the key bound to the statement's builder.id.
    ``authorized_builders``: dict builder.id -> signing key_id (the
    builder allowlist; operator-owned).
    ``ingestor_signer``: gov.signing.Signer whose key re-seals the
    translated statements.
    ``built_at``: epoch seconds for the translated statements
    (informational; caller-supplied).

    Returns SlsaIngestion. Raises SlsaPredicateError loudly on any
    violation -- including a VALID signature from a key that is not
    bound to the claimed builder.id.
    """
    verifiers = list(verifiers) if isinstance(verifiers,
                                              (list, tuple)) else []
    if not verifiers or not all(isinstance(v, Verifier) for v in verifiers):
        raise SlsaPredicateError("verifiers must be a non-empty list of "
                                 "gov.signing.Verifier")
    if not isinstance(ingestor_signer, Signer):
        raise SlsaPredicateError("ingestor_signer must be a "
                                 "gov.signing.Signer")
    if not isinstance(built_at, int) or built_at < 0:
        raise SlsaPredicateError("built_at must be a non-negative int")
    builders = _strict_authorized_builders(authorized_builders)

    # 1. DSSE envelope validation; the payloadType is pinned -- a SLSA
    # statement arriving in any other envelope type is refused.
    try:
        payload, payload_type, _ = _de.parse_envelope(envelope)
    except _de.EnvelopeError as exc:
        raise SlsaPredicateError("envelope refused: %s" % exc)
    if payload_type != INTOTO_PAYLOAD_TYPE:
        raise SlsaPredicateError(
            "payloadType %r refused: SLSA statements must arrive as %r"
            % (payload_type, INTOTO_PAYLOAD_TYPE))

    # 2. Statement/v1 strict parse + predicate dispatch.
    doc = parse_statement_payload(payload)
    predicate = doc["predicate"]
    build_def = predicate["buildDefinition"]
    run_details = predicate["runDetails"]
    builder_id = run_details["builder"]["id"]

    # 3. Builder allowlist + key binding: the signature must come from
    # the key BOUND to the claimed builder.id. A valid signature from
    # any other trusted key is a REFUSAL (the cosign rule: bind digest
    # + expected identity + issuer).
    if builder_id not in builders:
        raise SlsaPredicateError(
            "builder %r is not in the authorized-builder allowlist "
            "(refused: valid signature from an unknown builder is not "
            "a pass)" % builder_id)
    expected_key_id = builders[builder_id]
    builder_verifier = None
    for verifier in verifiers:
        if verifier.key_id == expected_key_id:
            builder_verifier = verifier
            break
    if builder_verifier is None:
        raise SlsaPredicateError(
            "no verifier for the key %r bound to builder %r"
            % (expected_key_id, builder_id))
    # NOTE: `payload` is the byte-string decoded from this same envelope
    # in step 1, so open_envelope's payload-binding check is a no-op here
    # by construction -- the tamper refusal rests on the PAE signature
    # check (probes S4/S9), which is the correct authority.
    try:
        _de.open_envelope(envelope, payload, INTOTO_PAYLOAD_TYPE,
                          [builder_verifier], threshold=1)
    except _de.EnvelopeError as exc:
        raise SlsaPredicateError(
            "builder signature invalid for builder %r (key %s): %s"
            % (builder_id, expected_key_id, exc))

    # 4. Field translation. The recipe is digest-pinned BY CONSTRUCTION:
    # the sha256 of the canonical buildDefinition that was just
    # signature-verified. Materials become digest-pinned inputs marked
    # non-deterministic (evidence, not promises -- see module
    # docstring).
    predicate_sha256 = hashlib.sha256(_canonical(build_def)).hexdigest()
    recipe = "slsa-provenance/v1@sha256:" + predicate_sha256
    materials = [(m["uri"], m["digest"]["sha256"])
                 for m in build_def["resolvedDependencies"]]
    inputs = [_bp.ProvenanceInput(name=uri, digest_hex=digest,
                                  deterministic=False)
              for uri, digest in materials]
    subjects = {}
    sealed = {}
    for sub in doc["subject"]:
        name = sub["name"]
        digest = sub["digest"]["sha256"]
        subjects[name] = digest
        try:
            stmt = _bp.ProvenanceStatement(
                builder=builder_id, recipe=recipe, inputs=inputs,
                artifact_hex=digest, built_at=built_at)
        except _bp.ProvenanceError as exc:
            raise SlsaPredicateError("translation failed for subject "
                                     "%r: %s" % (name, exc))
        sealed[name] = _bp.seal_statement(stmt, ingestor_signer)

    envelope_sha256 = hashlib.sha256(
        _canonical(envelope)).hexdigest()
    return SlsaIngestion(
        builder_id=builder_id,
        build_type=build_def["buildType"],
        predicate_sha256=predicate_sha256,
        envelope_sha256=envelope_sha256,
        ingestor_key_id=ingestor_signer.key_id,
        built_at=built_at,
        subjects=subjects,
        materials=materials,
        sealed=sealed,
    )


def chain_inputs(ingestion):
    """(named_statements, artifacts) for verify_provenance_chain from a
    SlsaIngestion -- the only supported path (see SlsaIngestion). The
    name binding comes from the signature-verified subject list (not
    caller-supplied receipts), which closes the provenance_verifier
    name-binding residual for the SLSA path."""
    if not isinstance(ingestion, SlsaIngestion):
        raise SlsaPredicateError("chain_inputs requires a SlsaIngestion")
    return ingestion.chain_inputs()
