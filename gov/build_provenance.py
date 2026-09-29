"""Build-provenance records: what built an artifact, bound to its digest.

PATTERN LINEAGE: Nix/Guix's build-provenance idea (reproducible builds:
a derivation records builder, recipe, and inputs so a verifier can
re-derive the output) and in-toto/DSSE's statement pattern (a signed
predicate that MUST bind the artifact digest, or a valid signature is
meaningless). Reimplemented in stdlib Python -- no Nix/Guix/in-toto code
is vendored here, only the pattern.

A ``ProvenanceStatement`` records the build of one artifact::

    builder     -- who built it (builder identity string)
    recipe      -- the build recipe reference (e.g. repo@sha256:<hex>)
    inputs      -- list of ProvenanceInput {name, digest_hex, deterministic}
    artifact    -- the artifact's sha256 hex digest (THE binding)
    built_at    -- epoch seconds (informational only; never trusted as
                   freshness -- provenance is evidence, not authorization)

The reproducibility descriptor (each input's ``deterministic`` flag) is
the honest core: inputs marked deterministic MUST re-derive their digest
under the supplied rebuilder or the statement is a lie and verification
fails LOUD. Inputs marked non-deterministic (timestamps, random seeds,
network fetches) are evidence, not promises -- they cannot be
re-derived, and the verifier must not pretend otherwise.

The signed binding: ``seal`` signs the canonical statement body, which
INCLUDES the artifact digest. ``verify_sealed_statement`` requires the
caller's expected artifact digest to match, so a valid signature for
artifact A opened against artifact B is refused. Provenance is digest
identity -- ``gov.digest_ref.DigestRef`` semantics apply to the
artifact hex (64 lowercase hex, sha256, no tags).

Strictness: documents carry an exact field allowlist; unknown fields
are refused (fail-closed). ``ProvenanceError`` is raised loudly on any
violation -- the Verifier interface returns True/False internally but
the public seams here raise, because a silent False on a provenance
check is an invitation to skip it.

Stdlib only. $0 spend. Synthetic/local testing.
"""

import hashlib
import json

from .digest_ref import DigestRef
from .signing import Verifier

__all__ = [
    "STATEMENT_FORMAT",
    "ProvenanceError",
    "ProvenanceInput",
    "ProvenanceStatement",
    "parse_statement",
    "seal_statement",
    "statement_digest",
    "verify_sealed_statement",
    "verify_reproducibility",
]

STATEMENT_FORMAT = "sasanam-provenance/v1"

_STATEMENT_FIELDS = frozenset(
    {"format", "builder", "recipe", "inputs", "artifact", "built_at"})
_INPUT_FIELDS = frozenset({"name", "digest", "deterministic"})
_SEALED_FIELDS = frozenset({"statement", "signature", "key_id"})


class ProvenanceError(ValueError):
    """Raised loudly on any provenance verification failure."""


def _check_hex_digest(value, where):
    if not isinstance(value, str):
        raise ProvenanceError("%s: digest must be str, got %s"
                              % (where, type(value).__name__))
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ProvenanceError("%s: not a sha256 hex digest: %r"
                              % (where, value))
    return value


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _strict_doc(doc, allowed, where):
    if not isinstance(doc, dict):
        raise ProvenanceError("%s: document must be a dict" % where)
    extra = set(doc) - allowed
    if extra:
        raise ProvenanceError("%s: unknown field(s) refused: %s"
                              % (where, sorted(extra)))
    return doc


class ProvenanceInput(object):
    """One build input: name, sha256 digest, and the determinism claim."""

    __slots__ = ("name", "digest_hex", "deterministic")

    def __init__(self, name, digest_hex, deterministic):
        if not isinstance(name, str) or not name:
            raise ProvenanceError("input name must be a non-empty str")
        self.name = name
        self.digest_hex = _check_hex_digest(digest_hex,
                                            "ProvenanceInput(%r)" % name)
        if not isinstance(deterministic, bool):
            raise ProvenanceError("deterministic must be bool for %r" % name)
        self.deterministic = deterministic

    def to_doc(self):
        return {"name": self.name, "digest": self.digest_hex,
                "deterministic": self.deterministic}


class ProvenanceStatement(object):
    """A build-provenance claim, unsigned until sealed."""

    __slots__ = ("builder", "recipe", "inputs", "artifact_hex", "built_at")

    def __init__(self, builder, recipe, inputs, artifact_hex, built_at):
        if not isinstance(builder, str) or not builder:
            raise ProvenanceError("builder must be a non-empty str")
        if not isinstance(recipe, str) or not recipe:
            raise ProvenanceError("recipe must be a non-empty str")
        # recipe should be digest-pinned; DigestRef refuses tag-only refs.
        try:
            DigestRef.parse(recipe)
        except Exception as exc:
            raise ProvenanceError("recipe must be a digest-pinned "
                                  "reference (repo@sha256:<hex>): %s" % exc)
        if not isinstance(inputs, (list, tuple)) or not inputs:
            raise ProvenanceError("inputs must be a non-empty list")
        for i in inputs:
            if not isinstance(i, ProvenanceInput):
                raise ProvenanceError("inputs must be ProvenanceInput "
                                      "instances")
        self.builder = builder
        self.recipe = recipe
        self.inputs = list(inputs)
        self.artifact_hex = _check_hex_digest(artifact_hex, "artifact")
        if not isinstance(built_at, int) or built_at < 0:
            raise ProvenanceError("built_at must be a non-negative int")
        self.built_at = built_at

    def to_doc(self):
        return {
            "format": STATEMENT_FORMAT,
            "builder": self.builder,
            "recipe": self.recipe,
            "inputs": [i.to_doc() for i in self.inputs],
            "artifact": self.artifact_hex,
            "built_at": self.built_at,
        }

    def seal(self, signer):
        """Sign this statement; returns the sealed document.

        The signature binds the statement body and the signing key
        (domain-separated). Human-readable context belongs in the
        envelope layer (gov.signature_envelope_v2), where trusted
        comments are bound into the signature; statement-level sealing
        is the raw signed predicate.
        """
        return seal_statement(self, signer)


def _sig_body(statement_doc, key_id):
    # Domain-separated signing body: the signature binds the statement
    # and the signing key. (Human-readable context lives in the
    # envelope layer, gov.signature_envelope_v2, where trusted
    # comments are bound into the signature.)
    return _canonical({
        "domain": "sasanam-provenance-seal/v1",
        "statement": statement_doc,
        "key_id": key_id,
    })


def seal_statement(statement, signer):
    """Sign ``statement``; returns {"statement", "signature", "key_id"}."""
    if not isinstance(statement, ProvenanceStatement):
        raise ProvenanceError("seal_statement requires a "
                              "ProvenanceStatement")
    doc = statement.to_doc()
    body = _sig_body(doc, signer.key_id)
    sig = signer.sign(body)
    return {"statement": doc, "signature": sig.hex(),
            "key_id": signer.key_id}


def parse_statement(sealed):
    """Strict-parse a sealed statement; refuses unknown fields."""
    _strict_doc(sealed, _SEALED_FIELDS, "sealed statement")
    doc = _strict_doc(sealed["statement"], _STATEMENT_FIELDS, "statement")
    if doc.get("format") != STATEMENT_FORMAT:
        raise ProvenanceError("unsupported statement format: %r"
                              % (doc.get("format"),))
    inputs = []
    for raw in doc["inputs"]:
        _strict_doc(raw, _INPUT_FIELDS, "input")
        if not isinstance(raw["deterministic"], bool):
            raise ProvenanceError("input deterministic must be bool")
        inputs.append(ProvenanceInput(name=raw["name"],
                                      digest_hex=raw["digest"],
                                      deterministic=raw["deterministic"]))
    stmt = ProvenanceStatement(builder=doc["builder"], recipe=doc["recipe"],
                               inputs=inputs, artifact_hex=doc["artifact"],
                               built_at=doc["built_at"])
    sig_hex = sealed["signature"]
    if (not isinstance(sig_hex, str) or len(sig_hex) != 128
            or any(c not in "0123456789abcdef" for c in sig_hex)):
        raise ProvenanceError("signature must be 128 lowercase hex chars")
    key_id = sealed["key_id"]
    if not isinstance(key_id, str) or not key_id:
        raise ProvenanceError("key_id must be a non-empty str")
    return stmt, bytes.fromhex(sig_hex), key_id


def verify_sealed_statement(sealed, expected_artifact_hex, verifier):
    """Verify signature AND the artifact binding. Raises loudly."""
    if not isinstance(verifier, Verifier):
        raise ProvenanceError("verifier must be a gov.signing.Verifier")
    stmt, sig, key_id = parse_statement(sealed)
    if key_id != verifier.key_id:
        raise ProvenanceError("statement key_id %r does not match "
                              "verifier key_id %r" % (key_id, verifier.key_id))
    # The artifact binding: the caller's expected digest must equal the
    # signed artifact digest. This is what makes provenance forgery
    # (valid signature, wrong artifact) fail.
    expected = _check_hex_digest(expected_artifact_hex, "expected_artifact")
    if stmt.artifact_hex != expected:
        raise ProvenanceError("artifact binding mismatch: statement is "
                              "for %s, expected %s"
                              % (stmt.artifact_hex, expected))
    body = _sig_body(stmt.to_doc(), key_id)
    if not verifier.verify(body, sig):
        raise ProvenanceError("statement signature invalid")
    return stmt


def statement_digest(sealed):
    """Canonical sha256 of the sealed statement (for envelope binding)."""
    stmt, _, _ = parse_statement(sealed)
    return hashlib.sha256(_canonical(stmt.to_doc())).hexdigest()


def verify_reproducibility(sealed, rebuilder, verifier,
                           expected_artifact_hex):
    """Verify signature+binding, then re-derive deterministic inputs.

    ``rebuilder(name)`` must return the sha256 hex digest the build
    would produce for input ``name``. Every input marked deterministic
    must re-derive to its recorded digest; a mismatch is a
    reproducibility LIE and raises loudly. Non-deterministic inputs are
    evidence, not promises: they are not re-derived, and the caller is
    told exactly which inputs were checked and which were not.

    The expected artifact digest is a parameter, not read from the
    statement: passing the statement's own claim would make the
    artifact binding vacuous.
    """
    stmt = verify_sealed_statement(
        sealed, expected_artifact_hex=expected_artifact_hex,
        verifier=verifier)
    if not callable(rebuilder):
        raise ProvenanceError("rebuilder must be callable")
    checked, unchecked = [], []
    for inp in stmt.inputs:
        if inp.deterministic:
            got = rebuilder(inp.name)
            if not isinstance(got, str):
                raise ProvenanceError("rebuilder must return hex digests")
            if got != inp.digest_hex:
                raise ProvenanceError(
                    "reproducibility lie: input %r claimed deterministic "
                    "with digest %s, rebuild produced %s"
                    % (inp.name, inp.digest_hex, got))
            checked.append(inp.name)
        else:
            unchecked.append(inp.name)
    return {"checked": checked, "unchecked": unchecked}
