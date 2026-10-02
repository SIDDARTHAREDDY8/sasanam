"""Provenance claims for evidence bundles: the BuildKit-pattern layer (clean-room).

Pattern lineage: moby/buildkit (Apache-2.0). This module reimplements the
*mechanisms* only -- the SLSA provenance predicate shape (build inputs
identified by DIGEST, not name alone), the completeness-marking
discipline (every material marked ``verified``/``unverified``; an
unverified input is LOUDLY marked, never silently dropped -- the
unverified-vcs-marking precedent), and the honesty discipline (the
claim records what the builder SAYS, and the verifier checks the
marking, never trusts it). No BuildKit code is vendored, imported, or
translated line-by-line; stdlib only.

Claim shape (unsigned)::

    {
      "claim_format": "sasanam-provenance/1",
      "builder": {"id": <builder id>, "keyid": <key id>},
      "artifact": {"digest": <64 hex>, "kind": <str>},
      "materials": [{"uri": <str>, "digest": <64 hex>,
                     "completeness": "verified" | "unverified"} ...],
      "invocation": {<opaque builder-declared build parameters>},
      "issued_at": <int unix time>,
      "rebuild_recipe": <optional re-derivation recipe, inside the
        signed bytes>,
    }

A re-derivation recipe (``sasanam-rebuild/1``)::

    {
      "recipe_format": "sasanam-rebuild/1",
      "inputs": [<material uri>, ...],     # subset of claim materials
      "steps": [{"op": "concat", "order": [<uri>, ...]},
                ...,
                {"op": "sha256"}],          # terminal hash is mandatory
    }

The closed transform vocabulary is concat/sha256/hex/prefix/suffix/
slice -- recipes describe, they never execute code. The verifier
re-executes the recipe over verifier-supplied material bytes and the
derived digest must equal the claimed artifact digest
(``provenance-rebuild-mismatch`` on disagreement -- the oss-rebuild
re-derivation pattern: evidence carries the procedure to reproduce
the proof).

Signed envelope::

    {"provenance": <claim>, "signature": <128 hex>, "keyid": <key id>}

``signature`` is Ed25519 over the canonical claim bytes (sort_keys,
compact separators, UTF-8). The builder's key is pinned in a
``BuilderPolicy`` allowlist owned by the AUDITOR (out-of-band key
distribution, same posture as the anchor and receipt modules); the
envelope's ``keyid`` is informational -- the pinned key does the work.

Verifier-side policy (fail closed):

* unsigned/malformed envelopes refuse ``provenance-signature-invalid`` /
  ``provenance-envelope-malformed`` -- unsigned-isn't-evidence (the
  wave-286 lesson: BuildKit's unsigned-isn't-evidence, Sonobuoy's
  unsigned bundles with zero non-repudiation);
* ``builder.id`` not in the allowlist refuses
  ``provenance-builder-untrusted`` -- a validly-signed claim from a
  foreign builder still refuses;
* a material missing its completeness marking refuses
  ``provenance-material-unmarked`` -- the honesty discipline is
  enforced, not assumed;
* a material marked ``unverified`` refuses
  ``provenance-material-unverified`` unless the verifier explicitly
  opts in (``allow_unverified_materials=True``) -- unverified inputs
  are LOUD, never silent;
* the anchor gate (``anchor_bundle_gated``) refuses
  ``provenance-missing`` when no provenance is supplied and
  ``provenance-artifact-mismatch`` when the claim is about a different
  artifact digest than the one being anchored.
* ``require_rebuild=True`` (or a builder named in the policy's
  ``rebuild_required`` set) demands re-derivation: missing recipe
  refuses ``provenance-rebuild-missing``; a re-derived digest that
  disagrees with the claimed artifact digest refuses
  ``provenance-rebuild-mismatch`` (critical -- possible tampering).

Composition:

* gov/evidence_anchor.py: ``anchor()`` / ``anchor_bundle()`` accept an
  optional ``provenance_gate`` callable invoked BEFORE the entry is
  sequenced; ``anchor_bundle_gated`` wires a verified provenance claim
  through it. The gate is additive: callers without provenance see no
  behavior change.
* gov/guac_graph.py: ``record_provenance_in_graph`` records the
  builder's attestation as STRUCTURAL edges (``software:builder/<id>@1
  -HasSLSA-> evidence:<provenance digest>``), following the
  ``record_anchor_in_graph`` precedent: claim edges are not used, and
  corroboration of the ARTIFACT stays in the claim layer
  (CertifyGood/CertifyBad) -- a builder cannot corroborate its own
  provenance by fiat.

THREAT MODEL (read this before trusting a provenance claim):

* Provenance attests what the builder CLAIMS about its inputs.
  Attestation != independent verification: a lying builder with a
  pinned key mints perfectly valid provenance for a dishonest build.
  What the claim DOES buy: non-repudiation (the builder cannot deny
  what it signed), completeness honesty (unverified inputs are
  visible, not hidden), and audit-time reconciliation against the
  witness-cosigned transparency log.
* The auditor's pinned builder key set is the trust anchor. Key
  distribution is out-of-band; this module cannot solve it.
* Re-derivation is software-side: a malicious builder with a pinned
  key can lie in the recipe (minting valid provenance for a
  dishonest build), and only DETECTION is the point -- the verifier
  re-executes and refuses on mismatch. A non-deterministic build can
  never re-derive: such recipes are refused at registration
  (``provenance-rebuild-invalid``), never silently accepted.
* Key reuse across builder ids is discouraged but not refused: there
  is no quorum here, so one key under two ids grants no extra power
  (unlike the F333 witness-quorum finding -- documented, not repeated).
"""

import hashlib
import json
import re

from gov import revocation_status as _revocation
import time

from gov import ed25519 as _ed25519

# ---------------------------------------------------------------------------
# Decision codes (domain: evidence-provenance). Registered in
# gov/decision_codes.py.
# ---------------------------------------------------------------------------

ARTIFACT_MISMATCH = "provenance-artifact-mismatch"
BUILDER_UNTRUSTED = "provenance-builder-untrusted"
ENVELOPE_MALFORMED = "provenance-envelope-malformed"
MATERIAL_UNMARKED = "provenance-material-unmarked"
MATERIAL_UNVERIFIED = "provenance-material-unverified"
MISSING = "provenance-missing"
SIGNATURE_INVALID = "provenance-signature-invalid"


class ProvenanceError(Exception):
    """Base class; carries the machine ``code``."""

    code = ENVELOPE_MALFORMED

    def __init__(self, message, code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


def _fail(code, detail):
    raise ProvenanceError(detail, code=code)


# ---------------------------------------------------------------------------
# Audit sink (deployment chains these into the HMAC audit log).
# Digests and ids only -- key material NEVER reaches the sink.
# ---------------------------------------------------------------------------

_EMIT = None


def set_emit(emit):
    """Install (or clear, with None) the audit-event sink."""
    global _EMIT
    _EMIT = emit


def _emit(event):
    """Emit an audit event to the installed sink. A broken audit sink
    must never break provenance issuance or verification: the sink
    failure is isolated (the failure mode is recorded in this
    docstring/comment, not the event -- the same trade-off as
    ``gov/timestamp_authority.py`` and ``gov/governed_exceptions.py``),
    never the sink's raw exception type escaping at a public seam
    (F345)."""
    if _EMIT is None:
        return
    try:
        _EMIT(dict(event))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Grammars and canonical bytes.
# ---------------------------------------------------------------------------

CLAIM_FORMAT = "sasanam-provenance/1"

_DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
_BUILDER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_KEYID_RE = re.compile(r"^[A-Za-z0-9._/-]{1,128}$")

COMPLETENESS_VALUES = ("verified", "unverified")


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def _check_digest(value, what):
    if not isinstance(value, str) or not _DIGEST_RE.match(value):
        _fail(ENVELOPE_MALFORMED,
              "%s must be 64 lowercase hex chars" % what)


# ---------------------------------------------------------------------------
# Builder policy: the auditor's pinned allowlist.
# ---------------------------------------------------------------------------

class BuilderPolicy:
    """Pinned builder allowlist.

    ``builders`` maps builder id -> Ed25519 public key (hex, 64 chars).
    The policy is constructed by the AUDITOR from out-of-band key
    distribution; an empty policy admits nothing and refuses
    ``provenance-builder-untrusted`` at build time (never a vacuous
    allow). Key reuse across builder ids is discouraged (documented in
    the module docstring) but not refused: without a quorum there is
    no escalation.

    ``rebuild_required`` names builder ids whose claims must re-derive
    (strict builder policy): verification of their claims demands a
    re-derivation recipe and refuses ``provenance-rebuild-missing``
    without one. Empty by default -- re-derivation is opt-in per
    builder, never a silent default that changes the admission
    posture.

    ``revocation_required`` names revocation ids (rids) whose signed
    status must be presented and enforced at verify time (opt-in
    revocation demand, same posture: empty by default, never a
    silent default).
    """

    def __init__(self, policy_id, builders, rebuild_required=(),
                 revocation_required=()):
        if not isinstance(policy_id, str) or \
                not _BUILDER_ID_RE.match(policy_id):
            _fail(ENVELOPE_MALFORMED, "policy id fails grammar")
        if not isinstance(builders, dict) or not builders:
            _fail(BUILDER_UNTRUSTED,
                  "builder policy admits no builders: vacuous policies "
                  "are refused at construction (they admit nothing)")
        self.builders = {}
        for bid, pub in builders.items():
            if not isinstance(bid, str) or not _BUILDER_ID_RE.match(bid):
                _fail(ENVELOPE_MALFORMED,
                      "builder id fails grammar: %r" % (bid,))
            if not isinstance(pub, str):
                _fail(ENVELOPE_MALFORMED,
                      "builder %r public key is not a string" % (bid,))
            try:
                raw = bytes.fromhex(pub)
            except ValueError:
                _fail(ENVELOPE_MALFORMED,
                      "builder %r public key is not hex" % (bid,))
            if len(raw) != 32:
                _fail(ENVELOPE_MALFORMED,
                      "builder %r public key is not 32 bytes" % (bid,))
            self.builders[bid] = pub.lower()
        if not isinstance(rebuild_required, (list, tuple, set, frozenset)):
            _fail(ENVELOPE_MALFORMED,
                  "rebuild_required must be a sequence of builder ids")
        req = set()
        for bid in rebuild_required:
            if not isinstance(bid, str) or not _BUILDER_ID_RE.match(bid):
                _fail(ENVELOPE_MALFORMED,
                      "rebuild_required builder id fails grammar: %r" %
                      (bid,))
            if bid not in self.builders:
                _fail(ENVELOPE_MALFORMED,
                      "rebuild_required names unknown builder %r" % (bid,))
            req.add(bid)
        self.rebuild_required = frozenset(req)
        # Revocation demand (opt-in): rids whose signed status must be
        # presented and enforced at verify time. Empty by default --
        # revocation enforcement changes no default admission posture
        # (honest default: enforcement stays opt-in until the
        # key-succession ceremony exists).
        if not isinstance(revocation_required,
                          (list, tuple, set, frozenset)):
            _fail(ENVELOPE_MALFORMED,
                  "revocation_required must be a sequence of rids")
        rreq = set()
        for rid in revocation_required:
            if not isinstance(rid, str) or \
                    not _revocation.RID_GRAMMAR.match(rid):
                _fail(ENVELOPE_MALFORMED,
                      "revocation_required rid fails grammar: %r" % (rid,))
            rreq.add(rid)
        self.revocation_required = frozenset(rreq)
        self.policy_id = policy_id

    def pubkey_for(self, builder_id):
        """Return the pinned pubkey hex for ``builder_id``.

        Refuses ``provenance-builder-untrusted`` LOUD when the builder
        is not allowlisted -- a validly-signed claim from a foreign
        builder still refuses.
        """
        try:
            return self.builders[builder_id]
        except KeyError:
            _fail(BUILDER_UNTRUSTED,
                  "builder %r is not in the allowlist" % (builder_id,))


# ---------------------------------------------------------------------------
# Claim construction (unsigned) and sealing.
# ---------------------------------------------------------------------------

def make_provenance_claim(builder_id, keyid, artifact_digest,
                          materials, invocation=None, issued_at=None,
                          artifact_kind="evidence-bundle",
                          rebuild_recipe=None):
    """Build the unsigned provenance claim dict.

    ``materials`` is a list of ``{"uri","digest","completeness"}``;
    enforcement of the marking discipline lives in
    ``verify_provenance`` (single enforcement point) -- this
    constructor only assembles. ``invocation`` is opaque
    builder-declared build parameters (kept inside the signed bytes).

    ``rebuild_recipe`` (optional) is a re-derivation recipe validated
    by ``check_rebuild_recipe`` at construction; it is stored inside
    the claim, so the sealed signature covers it.
    """
    if not isinstance(builder_id, str) or \
            not _BUILDER_ID_RE.match(builder_id):
        _fail(ENVELOPE_MALFORMED, "builder id fails grammar")
    if not isinstance(keyid, str) or not _KEYID_RE.match(keyid):
        _fail(ENVELOPE_MALFORMED, "keyid fails grammar")
    _check_digest(artifact_digest, "artifact digest")
    if not isinstance(materials, list):
        _fail(ENVELOPE_MALFORMED, "materials must be a list")
    for mat in materials:
        if not isinstance(mat, dict):
            _fail(ENVELOPE_MALFORMED, "material must be a dict")
    if rebuild_recipe is not None:
        check_rebuild_recipe(rebuild_recipe,
                             [m.get("uri") for m in materials])
    claim = {
        "claim_format": CLAIM_FORMAT,
        "builder": {"id": builder_id, "keyid": keyid},
        "artifact": {"digest": artifact_digest, "kind": artifact_kind},
        "materials": materials,
        "invocation": invocation if invocation is not None else {},
        "issued_at": issued_at if issued_at is not None
        else int(time.time()),
    }
    if rebuild_recipe is not None:
        claim["rebuild_recipe"] = rebuild_recipe
    return claim


def claim_digest(claim):
    """Content digest of the canonical claim bytes (the graph's
    evidence-node identity)."""
    return hashlib.sha256(_canonical(claim)).hexdigest()


def seal_provenance(claim, signer_seed):
    """Seal a claim into a signed envelope.

    Returns ``{"provenance": claim, "signature": <128 hex>,
    "keyid": claim["builder"]["keyid"]}``. The signature covers the
    canonical claim bytes exactly: every field the verifier checks is
    inside the signed payload.
    """
    if not isinstance(claim, dict):
        _fail(ENVELOPE_MALFORMED, "claim must be a dict")
    if not isinstance(signer_seed, (bytes, bytearray)):
        _fail(ENVELOPE_MALFORMED, "signer seed must be 32 bytes")
    seed = bytes(signer_seed)
    if len(seed) != 32:
        _fail(ENVELOPE_MALFORMED, "signer seed is not 32 bytes")
    builder = claim.get("builder")
    if not isinstance(builder, dict):
        _fail(ENVELOPE_MALFORMED, "claim.builder must be a dict")
    keyid = builder.get("keyid", "")
    sig = _ed25519.sign(seed, _canonical(claim)).hex()
    return {"provenance": claim, "signature": sig, "keyid": keyid}


# ---------------------------------------------------------------------------
# Verification (the single enforcement point).
# ---------------------------------------------------------------------------

def _check_claim_shape(claim):
    if not isinstance(claim, dict):
        _fail(ENVELOPE_MALFORMED, "provenance claim must be a dict")
    if claim.get("claim_format") != CLAIM_FORMAT:
        _fail(ENVELOPE_MALFORMED,
              "claim_format must be %r" % (CLAIM_FORMAT,))
    builder = claim.get("builder")
    if not isinstance(builder, dict):
        _fail(ENVELOPE_MALFORMED, "claim.builder must be a dict")
    bid = builder.get("id")
    if not isinstance(bid, str) or not _BUILDER_ID_RE.match(bid):
        _fail(ENVELOPE_MALFORMED, "builder id fails grammar")
    artifact = claim.get("artifact")
    if not isinstance(artifact, dict):
        _fail(ENVELOPE_MALFORMED, "claim.artifact must be a dict")
    _check_digest(artifact.get("digest"), "artifact digest")
    materials = claim.get("materials")
    if not isinstance(materials, list):
        _fail(ENVELOPE_MALFORMED, "claim.materials must be a list")
    for mat in materials:
        if not isinstance(mat, dict):
            _fail(ENVELOPE_MALFORMED, "material must be a dict")
        uri = mat.get("uri")
        if not isinstance(uri, str) or not uri or len(uri) > 512:
            _fail(ENVELOPE_MALFORMED,
                  "material uri must be a non-empty str <= 512 chars")
        _check_digest(mat.get("digest"), "material digest")
    issued = claim.get("issued_at")
    if not isinstance(issued, int) or isinstance(issued, bool) \
            or issued < 0:
        _fail(ENVELOPE_MALFORMED, "issued_at must be a non-negative int")
    recipe = claim.get("rebuild_recipe")
    if recipe is not None:
        check_rebuild_recipe(recipe, [m["uri"] for m in materials])
    return bid


def verify_provenance(envelope, builder_policy,
                      allow_unverified_materials=False,
                      require_rebuild=False, material_bytes=None,
                      revocation_gate=None, revocation_statuses=()):
    """Verify a provenance envelope LOUD. Returns True.

    Checks, in order: envelope shape -> claim shape (the honesty
    discipline is enforced here: every material must carry an explicit
    ``completeness`` marking) -> builder.id in the allowlist (foreign
    builders refuse even when validly signed) -> Ed25519 signature
    verifies under the PINNED key (the envelope's keyid is
    informational) -> material markings: unmarked refuses
    ``provenance-material-unmarked``; ``unverified`` refuses
    ``provenance-material-unverified`` unless the verifier explicitly
    opts in -> optional re-derivation. Any failure raises
    ProvenanceError with its machine code.

    ``require_rebuild=True`` (with ``material_bytes``) demands that
    the claim's artifact digest re-derive from the signed recipe and
    the supplied materials: missing recipe refuses
    ``provenance-rebuild-missing``, disagreement refuses
    ``provenance-rebuild-mismatch``. A builder named in the policy's
    ``rebuild_required`` set triggers the same demand even without
    the kwarg (strict builder policy).

    Revocation demand (opt-in): when the policy's
    ``revocation_required`` is non-empty, the caller must pass a
    ``revocation_gate`` (a ``gov.revocation_status.RevocationGate``
    bound to the pinned registry key) and signed status envelopes in
    ``revocation_statuses`` covering every demanded rid. The gate
    verifies and enforces each status: a retired rid refuses
    ``revocation-retired-reuse``, a revoked rid refuses
    ``revocation-revoked``, missing coverage refuses
    ``revocation-status-unverifiable``. A non-empty demand without a
    gate refuses fail-closed -- a demand without a trust anchor is a
    misconfiguration, never a silent pass. With an empty
    ``revocation_required`` the default posture is unchanged.
    """
    if not isinstance(envelope, dict):
        _fail(ENVELOPE_MALFORMED, "envelope must be a dict")
    claim = envelope.get("provenance")
    sig_hex = envelope.get("signature")
    if claim is None or sig_hex is None:
        _fail(ENVELOPE_MALFORMED,
              "envelope must carry provenance and signature")
    if not isinstance(builder_policy, BuilderPolicy):
        _fail(ENVELOPE_MALFORMED,
              "builder_policy must be a BuilderPolicy")
    builder_id = _check_claim_shape(claim)
    # Completeness marking: enforced BEFORE the signature check so a
    # claim that lies about its own honesty discipline is named for
    # what it is (unmarked), not merely for a bad signature.
    for mat in claim["materials"]:
        completeness = mat.get("completeness")
        if completeness not in COMPLETENESS_VALUES:
            _fail(MATERIAL_UNMARKED,
                  "material %r carries no valid completeness marking "
                  "(must be 'verified' or 'unverified')" % (mat.get("uri"),))
        if completeness == "unverified" and not allow_unverified_materials:
            _fail(MATERIAL_UNVERIFIED,
                  "material %r is marked unverified; the verifier did "
                  "not opt in" % (mat.get("uri"),))
    pub_hex = builder_policy.pubkey_for(builder_id)
    try:
        sig = bytes.fromhex(sig_hex)
    except (TypeError, ValueError):
        _fail(SIGNATURE_INVALID, "signature is not hex")
    if len(sig) != 64:
        _fail(SIGNATURE_INVALID, "signature is not 64 bytes")
    ok = _ed25519.verify(bytes.fromhex(pub_hex), _canonical(claim), sig)
    # Wave-243 lesson: gov.ed25519.verify returns True/False -- the
    # return must be checked, never assumed.
    if ok is not True:
        _fail(SIGNATURE_INVALID,
              "provenance signature does not verify under the pinned "
              "builder key")
    need_rebuild = bool(require_rebuild) or \
        builder_id in builder_policy.rebuild_required
    if need_rebuild:
        _rederive_and_compare(claim, builder_policy, material_bytes)
    need_revocation = bool(builder_policy.revocation_required)
    if need_revocation:
        if revocation_gate is None:
            _fail(_revocation.STATUS_UNVERIFIABLE,
                  "policy demands revocation status for rids %r but no "
                  "revocation gate was supplied: demand without a trust "
                  "anchor refuses fail-closed"
                  % (sorted(builder_policy.revocation_required),))
        revocation_gate.require_all(revocation_statuses)
    _emit({"event": "provenance-verified", "builder": builder_id,
           "artifact": claim["artifact"]["digest"],
           "digest": claim_digest(claim)})
    return True


# ---------------------------------------------------------------------------
# The anchor gate: provenance-gated anchoring.
# ---------------------------------------------------------------------------

def _gate_for(envelope, builder_policy, allow_unverified_materials,
              require_rebuild=False, material_bytes=None):
    """Build the ``provenance_gate`` callable for the anchor module.

    The gate verifies the envelope AND binds it to the digest being
    anchored: a provenance claim about artifact A never gates the
    anchoring of digest B (``provenance-artifact-mismatch``).
    """

    def gate(bundle_digest):
        verify_provenance(envelope, builder_policy,
                          allow_unverified_materials=
                          allow_unverified_materials,
                          require_rebuild=require_rebuild,
                          material_bytes=material_bytes)
        claimed = envelope["provenance"]["artifact"]["digest"]
        if claimed != bundle_digest:
            _fail(ARTIFACT_MISMATCH,
                  "provenance claim is about artifact %s, not the "
                  "anchored digest %s" % (claimed, bundle_digest))

    return gate


def anchor_bundle_gated(log, bundle_digest, provenance_envelope,
                        builder_policy, witness_policy=None,
                        witness_seeds=None,
                        allow_unverified_materials=False,
                        require_rebuild=False, material_bytes=None):
    """Anchor a bundle digest through the transparency log with the
    provenance gate armed.

    Refuses ``provenance-missing`` when no provenance envelope is
    supplied (missing provenance never anchors silently), then
    verifies the envelope, binds it to ``bundle_digest``, and anchors
    via ``gov/evidence_anchor.py``. The gate fires INSIDE ``anchor()``
    before the entry is sequenced: a refused bundle leaves no log
    entry. Returns the anchor receipt.

    ``require_rebuild=True`` (with ``material_bytes``) additionally
    demands re-derivation before sequencing: a strict builder policy
    refuses anchoring when the artifact digest cannot be re-derived
    from the signed recipe.
    """
    from gov import evidence_anchor as _ea
    if provenance_envelope is None:
        _fail(MISSING,
              "provenance-gated anchor requires a provenance envelope; "
              "missing provenance never anchors silently")
    gate = _gate_for(provenance_envelope, builder_policy,
                     allow_unverified_materials,
                     require_rebuild=require_rebuild,
                     material_bytes=material_bytes)
    return _ea.anchor(log, bundle_digest, witness_policy=witness_policy,
                      witness_seeds=witness_seeds, provenance_gate=gate)


# ---------------------------------------------------------------------------
# Re-derivation receipts: the oss-rebuild pattern (mechanism only, no
# code lifted -- Apache-2.0, google/oss-rebuild).
#
# "Evidence carries the PROCEDURE to reproduce the proof" -- stronger
# than "evidence carries its own verification contract". A provenance
# claim MAY carry a bounded, auditable ``rebuild_recipe`` describing
# how the artifact digest is deterministically re-derived from the
# declared materials. The verifier re-executes the recipe over
# verifier-supplied material bytes and compares the result to the
# claimed artifact digest.
#
# Recipes DESCRIBE; they never execute code, fetch from the network,
# or touch the host. The transform vocabulary is closed and pure:
# concat/sha256/hex/prefix/suffix/slice. A recipe naming anything
# else refuses ``provenance-rebuild-transform-unknown``. The recipe
# lives INSIDE the signed claim, so a substituted recipe breaks the
# builder signature before it ever reaches the interpreter.
#
# In the trust_vector verify/validate split, re-derivation IS the
# validate half: signature checks are the verify half (done inside
# verify_provenance), re-execution of the recipe is the validate half
# (done here, and surfaced to appraisal via rebuild_receipt()).
# ---------------------------------------------------------------------------

REBUILD_RECIPE_FORMAT = "sasanam-rebuild/1"

#: Closed deterministic transform vocabulary. Pure functions only;
#: every transform is total over well-typed inputs.
REBUILD_TRANSFORMS = ("concat", "sha256", "hex", "prefix", "suffix",
                      "slice")

#: Byte budgets: the verifier runs the recipe, so the recipe cannot
#: demand unbounded work. A violation refuses
#: ``provenance-rebuild-invalid`` (fail closed, never OOM).
MAX_REBUILD_INPUT_BYTES = 16 * 1024 * 1024
MAX_REBUILD_BUFFER_BYTES = 64 * 1024 * 1024
MAX_REBUILD_STEPS = 64
MAX_REBUILD_HEADER_BYTES = 4096

#: Scheme id for the appraisal seam (claim_digest, scheme_id,
#: endorsements) that gov/trust_vector.py consumes.
REBUILD_SCHEME_ID = "provenance-rebuild/v1"

REBUILD_INVALID = "provenance-rebuild-invalid"
REBUILD_MISMATCH = "provenance-rebuild-mismatch"
REBUILD_MISSING = "provenance-rebuild-missing"
TRANSFORM_UNKNOWN = "provenance-rebuild-transform-unknown"


def check_rebuild_recipe(recipe, material_uris):
    """Validate a re-derivation recipe against the claim's materials.

    ``material_uris`` is the set of URIs declared in the claim; every
    recipe input must name one of them. Returns True. Refusals are
    LOUD and coded: ``provenance-rebuild-transform-unknown`` for an
    unlisted transform, ``provenance-rebuild-invalid`` for anything
    else (a non-deterministic-by-construction recipe -- inputs that
    cannot be named, unbounded work, a missing terminal hash -- can
    never re-derive, so it is refused at registration).
    """
    if not isinstance(recipe, dict):
        _fail(REBUILD_INVALID, "rebuild recipe must be a dict")
    if recipe.get("recipe_format") != REBUILD_RECIPE_FORMAT:
        _fail(REBUILD_INVALID,
              "recipe_format must be %r" % (REBUILD_RECIPE_FORMAT,))
    inputs = recipe.get("inputs")
    if not isinstance(inputs, list) or not inputs:
        _fail(REBUILD_INVALID, "recipe inputs must be a non-empty list")
    if material_uris is None:
        material_uris = []
    if not isinstance(material_uris, (list, tuple, set, frozenset)) or \
            any(not isinstance(uri, str) for uri in material_uris):
        _fail(REBUILD_INVALID,
              "material_uris must be a sequence of URI strings")
    known = set(material_uris)
    for uri in inputs:
        if not isinstance(uri, str) or uri not in known:
            _fail(REBUILD_INVALID,
                  "recipe input %r is not a declared material" % (uri,))
    if len(set(inputs)) != len(inputs):
        _fail(REBUILD_INVALID, "recipe inputs must be unique")
    steps = recipe.get("steps")
    if not isinstance(steps, list) or not steps or \
            len(steps) > MAX_REBUILD_STEPS:
        _fail(REBUILD_INVALID,
              "recipe steps must be a non-empty list of at most %d" %
              MAX_REBUILD_STEPS)
    input_set = set(inputs)
    for i, step in enumerate(steps):
        _check_rebuild_step(step, i, input_set)
    last = steps[-1]
    if set(last) != {"op"} or last["op"] != "sha256":
        _fail(REBUILD_INVALID,
              "recipe must end with a terminal {\"op\": \"sha256\"} step: "
              "the artifact digest is the sha256 hex of the recipe's "
              "pre-image")
    return True


def _check_rebuild_step(step, i, inputs):
    """Validate one recipe step. Grammar errors refuse
    ``provenance-rebuild-invalid``; an op outside the closed vocabulary
    refuses ``provenance-rebuild-transform-unknown``."""
    label = "recipe step %d" % i
    if not isinstance(step, dict):
        _fail(REBUILD_INVALID, label + " must be a dict")
    op = step.get("op")
    if op not in REBUILD_TRANSFORMS:
        _fail(TRANSFORM_UNKNOWN,
              "%s names unknown transform %r" % (label, op))
    if op == "concat":
        if set(step) != {"op", "order"}:
            _fail(REBUILD_INVALID, label + ": concat takes only 'order'")
        order = step["order"]
        if not isinstance(order, list) or not order:
            _fail(REBUILD_INVALID,
                  label + ": order must be a non-empty list")
        for uri in order:
            if not isinstance(uri, str) or uri not in inputs:
                _fail(REBUILD_INVALID,
                      label + ": order entry %r is not a declared recipe "
                      "input" % (uri,))
    elif op in ("prefix", "suffix"):
        if set(step) != {"op", "bytes"}:
            _fail(REBUILD_INVALID, label + ": %s takes only 'bytes'" % op)
        raw = step["bytes"]
        if not isinstance(raw, str) or not raw:
            _fail(REBUILD_INVALID,
                  label + ": bytes must be a non-empty hex string")
        try:
            blob = bytes.fromhex(raw)
        except ValueError:
            _fail(REBUILD_INVALID, label + ": bytes is not hex")
        if len(blob) > MAX_REBUILD_HEADER_BYTES:
            _fail(REBUILD_INVALID,
                  label + ": header literal exceeds %d bytes" %
                  MAX_REBUILD_HEADER_BYTES)
    elif op == "slice":
        if set(step) != {"op", "offset", "length"}:
            _fail(REBUILD_INVALID,
                  label + ": slice takes only offset/length")
        off, ln = step["offset"], step["length"]
        if not isinstance(off, int) or isinstance(off, bool) or off < 0:
            _fail(REBUILD_INVALID,
                  label + ": offset must be a non-negative int")
        if not isinstance(ln, int) or isinstance(ln, bool) or ln <= 0:
            _fail(REBUILD_INVALID,
                  label + ": length must be a positive int")
        if off + ln > MAX_REBUILD_BUFFER_BYTES:
            _fail(REBUILD_INVALID,
                  label + ": slice window exceeds the rebuild buffer "
                  "budget")
    else:  # sha256, hex: no parameters
        if set(step) != {"op"}:
            _fail(REBUILD_INVALID, label + ": %s takes no parameters" % op)
    return True


def execute_rebuild(recipe, material_bytes):
    """Execute a validated recipe over verifier-supplied material bytes.

    The recipe is self-validated here (``check_rebuild_recipe`` over
    the supplied materials): malformed recipes refuse LOUD and coded
    (``provenance-rebuild-invalid`` / ``provenance-rebuild-transform-
    unknown``), so no caller can bypass the registration gate by
    calling this seam directly. Returns the 32-byte digest (the recipe
    must end with a terminal ``sha256`` step). Execution trusts nothing
    and still bounds every operation (fail closed on budget
    violations).
    """
    # F356: the registration gate cannot be bypassed -- a direct call
    # self-validates before touching the materials.
    check_rebuild_recipe(recipe, set(material_bytes)
                         if isinstance(material_bytes, dict) else set())
    total = 0
    for uri in recipe["inputs"]:
        blob = material_bytes.get(uri) \
            if isinstance(material_bytes, dict) else None
        if not isinstance(blob, (bytes, bytearray)):
            _fail(REBUILD_INVALID,
                  "material %r bytes were not supplied as bytes" % (uri,))
        total += len(blob)
        if total > MAX_REBUILD_INPUT_BYTES:
            _fail(REBUILD_INVALID,
                  "recipe inputs exceed the %d-byte input budget" %
                  MAX_REBUILD_INPUT_BYTES)
    buf = b""
    for step in recipe["steps"]:
        op = step["op"]
        if op == "concat":
            buf = b"".join(bytes(material_bytes[u])
                           for u in step["order"])
        elif op == "sha256":
            buf = hashlib.sha256(buf).digest()
        elif op == "hex":
            buf = buf.hex().encode("ascii")
        elif op == "prefix":
            buf = bytes.fromhex(step["bytes"]) + buf
        elif op == "suffix":
            buf = buf + bytes.fromhex(step["bytes"])
        elif op == "slice":
            off, ln = step["offset"], step["length"]
            if off + ln > len(buf):
                _fail(REBUILD_INVALID,
                      "slice window %d:%d exceeds the %d-byte buffer" %
                      (off, off + ln, len(buf)))
            buf = buf[off:off + ln]
        if len(buf) > MAX_REBUILD_BUFFER_BYTES:
            _fail(REBUILD_INVALID,
                  "rebuild buffer exceeds the %d-byte budget" %
                  MAX_REBUILD_BUFFER_BYTES)
    return buf


def _rederive_and_compare(claim, builder_policy, material_bytes):
    """Re-derive the artifact digest and compare it to the claim.

    The recipe must already be trusted (it lives inside the signed
    claim; the caller verifies the signature first). Returns the
    derived 64-hex digest; mismatch refuses
    ``provenance-rebuild-mismatch`` (critical: recomputed evidence
    disagrees with the claim).
    """
    recipe = claim.get("rebuild_recipe")
    if recipe is None:
        _fail(REBUILD_MISSING,
              "the verifier demanded re-derivation but the claim "
              "carries no re-derivation recipe")
    check_rebuild_recipe(recipe, [m["uri"] for m in claim["materials"]])
    derived = execute_rebuild(recipe, material_bytes).hex()
    claimed = claim["artifact"]["digest"]
    if derived != claimed:
        _fail(REBUILD_MISMATCH,
              "re-derived digest %s disagrees with the claimed artifact "
              "digest %s" % (derived, claimed))
    _emit({"event": "provenance-rebuild-verified",
           "builder": claim["builder"]["id"],
           "artifact": claimed,
           "digest": claim_digest(claim),
           "recipe": hashlib.sha256(_canonical(recipe)).hexdigest()})
    return derived


def verify_rebuild(envelope, builder_policy, material_bytes,
                   allow_unverified_materials=False):
    """Re-derive a claim's artifact digest LOUD. Returns the derived
    64-hex digest.

    Verifies the envelope first (fail closed: the recipe is only
    trustworthy inside a builder-signed, allowlisted claim), then
    re-executes the signed recipe over ``material_bytes`` (a dict
    mapping material URI -> bytes) and refuses
    ``provenance-rebuild-mismatch`` on disagreement. A claim with no
    recipe refuses ``provenance-rebuild-missing`` -- use
    ``verify_provenance`` when re-derivation is optional.
    """
    if not isinstance(envelope, dict):
        _fail(ENVELOPE_MALFORMED, "envelope must be a dict")
    if not isinstance(builder_policy, BuilderPolicy):
        _fail(ENVELOPE_MALFORMED,
              "builder_policy must be a BuilderPolicy")
    verify_provenance(envelope, builder_policy,
                      allow_unverified_materials=
                      allow_unverified_materials)
    return _rederive_and_compare(envelope["provenance"], builder_policy,
                                 material_bytes)


def rebuild_receipt(envelope, builder_policy, material_bytes,
                    allow_unverified_materials=False):
    """Build the appraisal-seam record for a verified re-derivation.

    Returns ``{"claim_digest": ..., "scheme_id": "provenance-rebuild/v1",
    "endorsement": {...}}`` -- the narrow (claim_digest, scheme_id,
    endorsements) seam gov/trust_vector.py consumes. The endorsement
    carries the re-derived digest, the builder, and the recipe digest:
    an appraiser can re-run the recipe itself from the claim's
    materials without trusting this receipt's word for it (the recipe
    digest names exactly which procedure was executed).
    """
    if not isinstance(envelope, dict):
        _fail(ENVELOPE_MALFORMED, "envelope must be a dict")
    if not isinstance(builder_policy, BuilderPolicy):
        _fail(ENVELOPE_MALFORMED,
              "builder_policy must be a BuilderPolicy")
    derived = verify_rebuild(envelope, builder_policy, material_bytes,
                             allow_unverified_materials=
                             allow_unverified_materials)
    claim = envelope["provenance"]
    return {
        "claim_digest": claim_digest(claim),
        "scheme_id": REBUILD_SCHEME_ID,
        "endorsement": {
            "builder_id": claim["builder"]["id"],
            "builder_policy": builder_policy.policy_id,
            "artifact_digest": claim["artifact"]["digest"],
            "derived_digest": derived,
            "recipe_digest": hashlib.sha256(
                _canonical(claim["rebuild_recipe"])).hexdigest(),
        },
    }


# ---------------------------------------------------------------------------
# GUAC composition: provenance claims as evidence nodes.
# ---------------------------------------------------------------------------

def record_provenance_in_graph(graph, provenance_envelope,
                               builder_policy,
                               allow_unverified_materials=False):
    """Record a verified provenance claim in a GUAC evidence graph.

    Verifies the envelope first (fail closed), then adds
    ``software:builder/<id>@1`` and ``evidence:<provenance digest>``
    nodes plus a structural ``HasSLSA`` edge -- the
    ``record_anchor_in_graph`` precedent. Claim edges are NOT used: a
    builder cannot corroborate its own provenance by fiat;
    corroboration of the ARTIFACT stays in the claim layer
    (CertifyGood/CertifyBad). Materials and the artifact binding live
    inside the signed claim; the evidence node IS the canonical claim
    digest.
    """
    from gov import guac_graph as _gg
    verify_provenance(provenance_envelope, builder_policy,
                      allow_unverified_materials=
                      allow_unverified_materials)
    claim = provenance_envelope["provenance"]
    builder_id = claim["builder"]["id"]
    prov_digest = claim_digest(claim)
    sw = graph.add_node("software", "builder/%s@1" % builder_id)
    ev = graph.add_node("evidence", prov_digest)
    graph.add_edge(sw, "HasSLSA", ev)
    _emit({"event": "provenance-graphed", "builder": builder_id,
           "digest": prov_digest})
    return {"software_node": sw, "evidence_node": ev}
