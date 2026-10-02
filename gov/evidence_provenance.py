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
    }

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
* Key reuse across builder ids is discouraged but not refused: there
  is no quorum here, so one key under two ids grants no extra power
  (unlike the F333 witness-quorum finding -- documented, not repeated).
"""

import hashlib
import json
import re
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
    """

    def __init__(self, policy_id, builders):
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
                          artifact_kind="evidence-bundle"):
    """Build the unsigned provenance claim dict.

    ``materials`` is a list of ``{"uri","digest","completeness"}``;
    enforcement of the marking discipline lives in
    ``verify_provenance`` (single enforcement point) -- this
    constructor only assembles. ``invocation`` is opaque
    builder-declared build parameters (kept inside the signed bytes).
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
    claim = {
        "claim_format": CLAIM_FORMAT,
        "builder": {"id": builder_id, "keyid": keyid},
        "artifact": {"digest": artifact_digest, "kind": artifact_kind},
        "materials": materials,
        "invocation": invocation if invocation is not None else {},
        "issued_at": issued_at if issued_at is not None
        else int(time.time()),
    }
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
    keyid = claim.get("builder", {}).get("keyid", "")
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
    return bid


def verify_provenance(envelope, builder_policy,
                      allow_unverified_materials=False):
    """Verify a provenance envelope LOUD. Returns True.

    Checks, in order: envelope shape -> claim shape (the honesty
    discipline is enforced here: every material must carry an explicit
    ``completeness`` marking) -> builder.id in the allowlist (foreign
    builders refuse even when validly signed) -> Ed25519 signature
    verifies under the PINNED key (the envelope's keyid is
    informational) -> material markings: unmarked refuses
    ``provenance-material-unmarked``; ``unverified`` refuses
    ``provenance-material-unverified`` unless the verifier explicitly
    opts in. Any failure raises ProvenanceError with its machine code.
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
    _emit({"event": "provenance-verified", "builder": builder_id,
           "artifact": claim["artifact"]["digest"],
           "digest": claim_digest(claim)})
    return True


# ---------------------------------------------------------------------------
# The anchor gate: provenance-gated anchoring.
# ---------------------------------------------------------------------------

def _gate_for(envelope, builder_policy, allow_unverified_materials):
    """Build the ``provenance_gate`` callable for the anchor module.

    The gate verifies the envelope AND binds it to the digest being
    anchored: a provenance claim about artifact A never gates the
    anchoring of digest B (``provenance-artifact-mismatch``).
    """

    def gate(bundle_digest):
        verify_provenance(envelope, builder_policy,
                          allow_unverified_materials=
                          allow_unverified_materials)
        claimed = envelope["provenance"]["artifact"]["digest"]
        if claimed != bundle_digest:
            _fail(ARTIFACT_MISMATCH,
                  "provenance claim is about artifact %s, not the "
                  "anchored digest %s" % (claimed, bundle_digest))

    return gate


def anchor_bundle_gated(log, bundle_digest, provenance_envelope,
                        builder_policy, witness_policy=None,
                        witness_seeds=None,
                        allow_unverified_materials=False):
    """Anchor a bundle digest through the transparency log with the
    provenance gate armed.

    Refuses ``provenance-missing`` when no provenance envelope is
    supplied (missing provenance never anchors silently), then
    verifies the envelope, binds it to ``bundle_digest``, and anchors
    via ``gov/evidence_anchor.py``. The gate fires INSIDE ``anchor()``
    before the entry is sequenced: a refused bundle leaves no log
    entry. Returns the anchor receipt.
    """
    from gov import evidence_anchor as _ea
    if provenance_envelope is None:
        _fail(MISSING,
              "provenance-gated anchor requires a provenance envelope; "
              "missing provenance never anchors silently")
    gate = _gate_for(provenance_envelope, builder_policy,
                     allow_unverified_materials)
    return _ea.anchor(log, bundle_digest, witness_policy=witness_policy,
                      witness_seeds=witness_seeds, provenance_gate=gate)


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
