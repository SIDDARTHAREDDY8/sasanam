"""C2PA-*shaped* provenance manifests for decision receipts and generated artifacts.

Wave-209 prospecting verdict (C2PA spec 2.2 -> ADAPT model / SKIP
conformance): the assertion/ingredient/hard-binding MODEL is adapted --
the standard assertion LABELS (``c2pa.actions``, ``c2pa.ingredient``,
``c2pa.hash.data``) so any C2PA-aware reader recognizes the vocabulary --
signed with our DSSE envelope. This is **C2PA-shaped, NOT
C2PA-conformant** (the GreenFlex precedent: "C2PA-compatible, not
C2PA-certified"): no JUMBF embedding, no COSE/X.509 claim signatures, no
conformance claim, no "Content Credentials" branding. A real C2PA
validator will reject these manifests; the value is vocabulary alignment
and the ingredient-chain discipline, not validator interop.

Spec-drift note 2026-09-29 (wave-212): the published C2PA spec is now 2.4
(we pin 2.2 vocabulary: ``c2pa.actions`` v1 and ``c2pa.ingredient`` v1 are
deprecated in 2.4 toward v2/v3; new section 18.28 ``c2pa.ai-disclosure``
assertion). Our ``c2pa.ai_generated`` action label is PRODUCT-LOCAL --
it appears nowhere in the 2.4 spec -- and stays honest only while this
module is explicitly C2PA-shaped, not conformant. Consider vocabulary
alignment (``c2pa.actions.v2``, ``c2pa.ingredient.v3``,
``c2pa.ai-disclosure``) in a future lane; this note records no gap.

The narrow claim is adopted verbatim from C2PA section 1.2 (guiding
principles): specifications "SHOULD NOT provide value judgments about
whether a given set of provenance data is 'good' or 'bad,' merely
whether the assertions included within can be validated as associated
with the underlying asset, correctly formed, and free from tampering."
A manifest proves ASSOCIATION AND INTEGRITY -- never the truth, safety,
or wisdom of the content. ``lint_no_value_judgment`` enforces this at
build time: free-text fields carrying judgment phrasing are refused.

The ingredient chain is the Decision BOM's missing vocabulary: every
transformation adds a new manifest that REFERENCES its parents by digest
rather than rewriting history. For a decision receipt the "ingredients"
are the model identity, the prompt, tool outputs, and prior decisions it
built on -- each cited by digest, never mutated.

Validation pipeline order (C2PA section 15, adapted): signature (DSSE) ->
assertions (shape) -> ingredients (chain walk) -> content hash (hard
binding). There is no timestamp assertion: the module is deterministic
(no clock, no randomness), so timestamps stay operator wall-clock and
are documented as such in the claim bounds.

The hard-binding rule (C2PA section 9.2, adapted): the manifest's
``c2pa.hash.data`` digest covers the artifact bytes; attaching the
manifest to different bytes (a transplant) fails verification. The
signature binds the manifest bytes themselves (DSSE/PAE), excluding
nothing -- the manifest has no self-embedding, so no exclusion range is
needed.

stdlib-only. Fail-closed: the single error vocabulary is
``C2PAManifestError``; ``gov.dsse_envelope.EnvelopeError`` is wrapped,
never leaked.
"""

import hashlib
import json
import os
import re

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

from . import claim_bounds as _cb
from . import dsse_envelope as _de

#: Manifest format label. Closed profile: a manifest whose format label
#: differs is refused -- the verifier must never silently accept a
#: manifest it was not built to understand.
FORMAT_LABEL = "c2pa-shaped-manifest/v1"
MANIFEST_VERSION = 1

#: The honest conformance label, checked on every verify path. A
#: manifest that claims conformance we do not have is refused.
CONFORMANCE_LABEL = "c2pa-shaped-not-conformant"

#: DSSE payload type for sealed manifests. Bound inside the signed
#: bytes (PAE), killing type-swap attacks.
PAYLOAD_TYPE = "application/vnd.sasanam.c2pa-shaped-manifest+json;v=1"

#: Closed action vocabulary (C2PA section 18.14, subset). Unknown
#: actions are refused: the verifier does not interpret prose.
KNOWN_ACTIONS = ("c2pa.created", "c2pa.edited", "c2pa.ai_generated")

#: Closed ingredient-role vocabulary. Every ingredient says what KIND
#: of parent it is, so an auditor can trace a decision receipt back to
#: the model version and the prompt digest without parsing prose.
KNOWN_ROLES = ("prompt", "model", "tool-output", "prior-decision",
               "policy", "evidence-bundle")

#: Chain-walk depth cap. A chain deeper than this is refused rather
#: than walked -- recursion must be bounded.
MAX_CHAIN_DEPTH = 64

#: Free-text fields (description, softwareAgent) must carry no value
#: judgments. Word-boundary matched on lowercased text: "incorrect"
#: does not trip on "correct", and "safety" (noun) is not banned --
#: only direct judgments about the content's worth.
_JUDGMENT_TOKENS = ("good", "bad", "safe", "unsafe", "trustworthy",
                    "untrustworthy", "correct", "incorrect",
                    "wise", "unwise")
_JUDGMENT_RE = re.compile(
    r"\b(" + "|".join(_JUDGMENT_TOKENS) + r")\b")


class C2PAManifestError(Exception):
    """Single fail-closed vocabulary for C2PA-shaped manifest violations."""


def _is_hex64(value):
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def _check_content_digest(value, where):
    if not _is_hex64(value):
        raise C2PAManifestError(
            "%s: content digest must be 64-char lowercase hex, got %r"
            % (where, value))
    return value


# ---------------------------------------------------------------- bounds

#: The canonical narrow statement for C2PA-shaped manifests: proves
#: association + integrity + chain continuity + action-format; disclaims
#: truth, safety, wisdom, signer trustworthiness, and completeness.
_DEFAULT_PROVES = [
    "manifest-integrity",
    "content-association",
    "ingredient-chain-continuity",
    "action-assertion-format",
]
_DEFAULT_DOES_NOT_PROVE = [
    "content-truth",
    "content-safety",
    "content-wisdom",
    "signer-trustworthiness",
    "provenance-completeness",
]
_DEFAULT_ASSUMPTIONS = [
    "verifier-trusts-issuer-keys",
    "stdlib-crypto-implementation-correct",
    "sha256-second-preimage-resistant",
]
_DEFAULT_SCOPE = [
    "json-shaped-not-jumbf",
    "dsse-signed-not-cose",
    "no-update-manifests-single-chain",
]


def default_manifest_bounds(where="claim_bounds"):
    """The canonical narrow claim-bounds for C2PA-shaped manifests,
    validated through ``gov/claim_bounds.py`` -- one primitive, every
    evidence shape."""
    return _cb.validate_bounds(
        {"proves": list(_DEFAULT_PROVES),
         "does_not_prove": list(_DEFAULT_DOES_NOT_PROVE),
         "verifier_assumptions": list(_DEFAULT_ASSUMPTIONS),
         "scope_limits": list(_DEFAULT_SCOPE)},
        where=where)


# ---------------------------------------------------------------- build

def _check_ingredient(ing, where):
    if not isinstance(ing, dict):
        raise C2PAManifestError("%s: ingredient must be a dict" % where)
    extra = set(ing) - {"ingredient_digest", "manifest_digest",
                        "relationship", "role"}
    if extra:
        raise C2PAManifestError(
            "%s: unknown ingredient field(s) refused: %s"
            % (where, sorted(extra)))
    _check_content_digest(ing.get("ingredient_digest"),
                          where + ".ingredient_digest")
    md = ing.get("manifest_digest")
    if md is not None and not _is_hex64(md):
        raise C2PAManifestError(
            "%s.manifest_digest: must be 64-char lowercase hex or None, "
            "got %r" % (where, md))
    if ing.get("relationship") != "parentOf":
        raise C2PAManifestError(
            "%s.relationship: must be 'parentOf', got %r"
            % (where, ing.get("relationship")))
    if ing.get("role") not in KNOWN_ROLES:
        raise C2PAManifestError(
            "%s.role: must be one of %s, got %r"
            % (where, list(KNOWN_ROLES), ing.get("role")))
    return {"ingredient_digest": ing["ingredient_digest"],
            "manifest_digest": md,
            "relationship": "parentOf",
            "role": ing["role"]}


def lint_no_value_judgment(manifest):
    """Refuse value-judgment phrasing in free-text fields.

    The narrow-claims rule (C2PA section 1.2) is enforced, not just
    documented: a description or softwareAgent that judges the content
    ("safe", "trustworthy", ...) is refused at build AND at verify, so
    a hand-rolled manifest cannot smuggle a judgment past the builder.
    """
    texts = []
    desc = manifest.get("description")
    if desc is not None:
        texts.append(("description", desc))
    actions = ((manifest.get("assertions") or {}).get("c2pa.actions")
               or {}).get("actions") or []
    for i, action in enumerate(actions):
        agent = action.get("softwareAgent") if isinstance(action, dict) \
            else None
        if agent is not None:
            texts.append(("c2pa.actions.actions[%d].softwareAgent" % i,
                          agent))
    for field, text in texts:
        if not isinstance(text, str):
            continue
        hit = _JUDGMENT_RE.search(text.lower())
        if hit:
            raise C2PAManifestError(
                "%s: value-judgment phrasing refused (%r) -- manifests "
                "prove association and integrity, never worth"
                % (field, hit.group(1)))
    return None


def build_manifest(*, content_digest, content_len, action, software_agent,
                   ingredients=None, digital_source_type="trainedAlgorithmicMedia",
                   description=None, claim_bounds=None):
    """Build a C2PA-shaped manifest for one artifact.

    ``content_digest`` is sha256 hex over the exact artifact bytes;
    ``action`` is one of KNOWN_ACTIONS; ``software_agent`` names the
    producing software (e.g. "sasanam-model v1.2.3"); ``ingredients``
    are parent references (each ``{"ingredient_digest", "manifest_digest"
    (or None for external inputs like prompts), "relationship":
    "parentOf", "role"}``). Duplicate parent manifests are refused --
    a chain must be a chain, not a multigraph.
    """
    _check_content_digest(content_digest, "content_digest")
    if isinstance(content_len, bool) or not isinstance(content_len, int) \
            or content_len < 0:
        raise C2PAManifestError(
            "content_len must be a non-negative int, got %r" % (content_len,))
    if action not in KNOWN_ACTIONS:
        raise C2PAManifestError(
            "action must be one of %s, got %r"
            % (list(KNOWN_ACTIONS), action))
    if not isinstance(software_agent, str) or not software_agent:
        raise C2PAManifestError(
            "software_agent must be a non-empty string")
    if not isinstance(digital_source_type, str) or not digital_source_type:
        raise C2PAManifestError(
            "digital_source_type must be a non-empty string")
    ings = []
    if ingredients is not None:
        if not isinstance(ingredients, list):
            raise C2PAManifestError("ingredients must be a list or None")
        seen = set()
        for i, ing in enumerate(ingredients):
            checked = _check_ingredient(ing, "ingredients[%d]" % i)
            md = checked["manifest_digest"]
            if md is not None:
                if md in seen:
                    raise C2PAManifestError(
                        "ingredients[%d]: duplicate parent manifest %s "
                        "refused" % (i, md))
                seen.add(md)
            ings.append(checked)
    bounds = default_manifest_bounds() if claim_bounds is None else None
    if bounds is None:
        try:
            bounds = _cb.validate_bounds(claim_bounds)
        except _cb.ClaimBoundsError as exc:
            raise C2PAManifestError(
                "claim_bounds invalid: %s" % (exc,))
    manifest = {
        "manifest_format": FORMAT_LABEL,
        "manifest_version": MANIFEST_VERSION,
        "conformance": CONFORMANCE_LABEL,
        "assertions": {
            "c2pa.actions": {
                "actions": [{
                    "action": action,
                    "softwareAgent": software_agent,
                    "digitalSourceType": digital_source_type,
                }],
            },
            "c2pa.ingredient": {"ingredients": ings},
            "c2pa.hash.data": {
                "algorithm": "sha256",
                "digest": content_digest,
                "content_len": content_len,
            },
        },
        "claim_bounds": bounds,
    }
    if description is not None:
        if not isinstance(description, str) or not description:
            raise C2PAManifestError(
                "description must be a non-empty string or None")
        manifest["description"] = description
    lint_no_value_judgment(manifest)
    return manifest


def canonical_manifest(manifest):
    """Deterministic canonical bytes of a manifest (the signed bytes)."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def manifest_digest(manifest):
    """sha256 over the canonical manifest -- the tamper-evident binding
    of the whole assertion set. A swapped assertion changes this digest."""
    return hashlib.sha256(canonical_manifest(manifest)).hexdigest()


# ---------------------------------------------------------------- verify

def verify_manifest_shape(manifest, where="manifest"):
    """Shape-check a manifest WITHOUT any crypto. Raises
    C2PAManifestError naming the offending field. Unknown assertion
    labels are refused -- the profile is closed."""
    if not isinstance(manifest, dict):
        raise C2PAManifestError("%s: manifest must be a dict" % where)
    if manifest.get("manifest_format") != FORMAT_LABEL:
        raise C2PAManifestError(
            "%s: manifest_format must be %r, got %r"
            % (where, FORMAT_LABEL, manifest.get("manifest_format")))
    if manifest.get("conformance") != CONFORMANCE_LABEL:
        raise C2PAManifestError(
            "%s: conformance must be %r -- manifests claiming conformance "
            "we do not have are refused, got %r"
            % (where, CONFORMANCE_LABEL, manifest.get("conformance")))
    assertions = manifest.get("assertions")
    if not isinstance(assertions, dict):
        raise C2PAManifestError("%s: assertions must be a dict" % where)
    extra = set(assertions) - {"c2pa.actions", "c2pa.ingredient",
                               "c2pa.hash.data"}
    if extra:
        raise C2PAManifestError(
            "%s: unknown assertion label(s) refused: %s"
            % (where, sorted(extra)))
    # c2pa.actions: the AI-generation label. Missing or malformed is
    # refused -- an unlabeled artifact must never pass as labeled.
    actions_node = assertions.get("c2pa.actions")
    if not isinstance(actions_node, dict):
        raise C2PAManifestError(
            "%s: c2pa.actions assertion missing or malformed" % where)
    actions = actions_node.get("actions")
    if not isinstance(actions, list) or not actions:
        raise C2PAManifestError(
            "%s: c2pa.actions.actions must be a non-empty list" % where)
    for i, action in enumerate(actions):
        awhere = "%s.c2pa.actions.actions[%d]" % (where, i)
        if not isinstance(action, dict):
            raise C2PAManifestError("%s: must be a dict" % awhere)
        if action.get("action") not in KNOWN_ACTIONS:
            raise C2PAManifestError(
                "%s.action: must be one of %s, got %r"
                % (awhere, list(KNOWN_ACTIONS), action.get("action")))
        agent = action.get("softwareAgent")
        if not isinstance(agent, str) or not agent:
            raise C2PAManifestError(
                "%s.softwareAgent: must be a non-empty string" % awhere)
        dst = action.get("digitalSourceType")
        if not isinstance(dst, str) or not dst:
            raise C2PAManifestError(
                "%s.digitalSourceType: must be a non-empty string" % awhere)
    # c2pa.ingredient: the parent references.
    ing_node = assertions.get("c2pa.ingredient")
    if not isinstance(ing_node, dict):
        raise C2PAManifestError(
            "%s: c2pa.ingredient assertion missing or malformed" % where)
    ingredients = ing_node.get("ingredients")
    if not isinstance(ingredients, list):
        raise C2PAManifestError(
            "%s: c2pa.ingredient.ingredients must be a list" % where)
    for i, ing in enumerate(ingredients):
        _check_ingredient(ing, "%s.c2pa.ingredient.ingredients[%d]"
                          % (where, i))
    # c2pa.hash.data: the hard binding.
    hash_node = assertions.get("c2pa.hash.data")
    if not isinstance(hash_node, dict):
        raise C2PAManifestError(
            "%s: c2pa.hash.data assertion missing or malformed" % where)
    if hash_node.get("algorithm") != "sha256":
        raise C2PAManifestError(
            "%s: c2pa.hash.data.algorithm must be 'sha256', got %r"
            % (where, hash_node.get("algorithm")))
    _check_content_digest(hash_node.get("digest"),
                          where + ".c2pa.hash.data.digest")
    clen = hash_node.get("content_len")
    if isinstance(clen, bool) or not isinstance(clen, int) or clen < 0:
        raise C2PAManifestError(
            "%s: c2pa.hash.data.content_len must be a non-negative int"
            % where)
    # Claim bounds are mandatory (wave-209): a boundless manifest is
    # refused, and bounds validate through the canonical primitive.
    bounds = manifest.get("claim_bounds")
    if bounds is None:
        raise C2PAManifestError(
            "%s: claim_bounds missing -- boundless manifests are refused"
            % where)
    try:
        _cb.validate_bounds(bounds, where + ".claim_bounds")
    except _cb.ClaimBoundsError as exc:
        raise C2PAManifestError(
            "%s: claim_bounds invalid: %s" % (where, exc))
    # The narrow-claims lint runs at verify too: a hand-rolled manifest
    # cannot smuggle a judgment past the builder.
    lint_no_value_judgment(manifest)
    return None


def verify_chain(manifest, ingredient_manifests, _depth=0, _path=()):
    """Walk the ingredient chain, verifying every generation.

    ``ingredient_manifests`` maps manifest digest -> manifest dict (the
    auditor's resolved store). Each ingredient whose ``manifest_digest``
    is set must resolve in the store; each resolved parent is
    shape-checked and its own hard-binding digest must equal the
    ``ingredient_digest`` the child recorded (the parent-content
    binding). Ingredients with ``manifest_digest`` None are external
    inputs (prompts, model cards without manifests) -- terminal roots,
    recorded but not walked. Missing parents (a skipped generation),
    cycles, and over-deep chains are refused.

    Returns the walked manifest digests in walk order (child first).

    Note on cycles: through a key-consistent store (every key equals
    the stored manifest's digest -- checked above) a true cycle is
    unconstructible, because a manifest's digest is fixed before any
    child can reference it. The ``_path`` cycle check is therefore
    defense-in-depth for internal/future callers, not a reachable
    public-API branch; the reachable termination guarantee is the
    depth cap.
    """
    if _depth > MAX_CHAIN_DEPTH:
        raise C2PAManifestError(
            "ingredient chain deeper than %d refused" % MAX_CHAIN_DEPTH)
    verify_manifest_shape(manifest, where="manifest")
    digest = manifest_digest(manifest)
    if digest in _path:
        raise C2PAManifestError(
            "ingredient chain cycle refused at manifest %s" % digest)
    if not isinstance(ingredient_manifests, dict):
        raise C2PAManifestError(
            "ingredient_manifests must be a dict of digest -> manifest")
    walked = [digest]
    path = _path + (digest,)
    ingredients = manifest["assertions"]["c2pa.ingredient"]["ingredients"]
    for i, ing in enumerate(ingredients):
        parent_digest = ing["manifest_digest"]
        if parent_digest is None:
            continue  # external input: a terminal root, not walked
        parent = ingredient_manifests.get(parent_digest)
        if parent is None:
            raise C2PAManifestError(
                "ingredient[%d]: parent manifest %s not in the supplied "
                "store -- a skipped generation is refused"
                % (i, parent_digest))
        if not isinstance(parent, dict):
            raise C2PAManifestError(
                "ingredient[%d]: store entry for %s is not a manifest"
                % (i, parent_digest))
        if manifest_digest(parent) != parent_digest:
            raise C2PAManifestError(
                "ingredient[%d]: store manifest digest does not match "
                "its key (swapped store entry)" % i)
        parent_content = parent["assertions"]["c2pa.hash.data"]["digest"]
        if parent_content != ing["ingredient_digest"]:
            raise C2PAManifestError(
                "ingredient[%d]: parent content digest %s does not match "
                "the recorded ingredient_digest %s (relabeled parent)"
                % (i, parent_content, ing["ingredient_digest"]))
        walked.extend(verify_chain(parent, ingredient_manifests,
                                   _depth=_depth + 1, _path=path))
    return walked


# ---------------------------------------------------------------- DSSE seal/open

def seal_manifest(manifest, signers):
    """Seal a manifest into a DSSE envelope. ``signers`` is a non-empty
    list of signer objects (``.sign(bytes)`` + ``.key_id``). The shape
    and lint are checked BEFORE signing: we never sign a malformed or
    judgment-carrying manifest."""
    verify_manifest_shape(manifest)
    if not signers:
        raise C2PAManifestError("seal_manifest requires at least one signer")
    try:
        return _de.seal(canonical_manifest(manifest), PAYLOAD_TYPE,
                        list(signers))
    except _de.EnvelopeError as exc:
        raise C2PAManifestError("seal failed: %s" % exc)


def open_manifest(envelope, expected_content_digest, verifiers, *,
                  ingredient_manifests=None, threshold=1):
    """Open and fully verify a sealed manifest.

    Pipeline order (C2PA section 15, adapted): signature (DSSE, checked
    before anything else) -> assertions (shape) -> ingredients (chain)
    -> content hash (hard binding against ``expected_content_digest`` --
    a manifest attached to different bytes is a transplant and is
    refused). Returns the verified manifest dict.
    """
    _check_content_digest(expected_content_digest,
                          "expected_content_digest")
    if not isinstance(envelope, dict):
        raise C2PAManifestError("envelope must be a dict")
    try:
        payload_bytes, payload_type, _parsed = _de.parse_envelope(envelope)
    except _de.EnvelopeError as exc:
        raise C2PAManifestError("envelope rejected: %s" % exc)
    if payload_type != PAYLOAD_TYPE:
        raise C2PAManifestError(
            "envelope payloadType must be %r, got %r"
            % (PAYLOAD_TYPE, payload_type))
    try:
        manifest = json.loads(payload_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise C2PAManifestError("manifest payload is not valid JSON: %s"
                                % exc)
    verify_manifest_shape(manifest)
    try:
        _de.open_envelope(envelope, payload_bytes, PAYLOAD_TYPE,
                          list(verifiers), threshold=threshold)
    except _de.EnvelopeError as exc:
        raise C2PAManifestError("manifest signature rejected: %s" % exc)
    if ingredient_manifests is not None:
        verify_chain(manifest, ingredient_manifests)
    bound = manifest["assertions"]["c2pa.hash.data"]["digest"]
    if bound != expected_content_digest:
        raise C2PAManifestError(
            "hard binding mismatch: manifest binds content %s but is "
            "attached to %s -- transplant refused"
            % (bound, expected_content_digest))
    return manifest


# ---------------------------------------------------------------- Decision BOM bridge

def bom_c2pa_section(manifest_digest_value, chain_length,
                     root_ingredient_digests):
    """Build the Decision BOM ``c2pa_provenance`` section (all-or-none).

    Binds the manifest the decision's receipt was sealed under, the
    walked chain length, and the direct parents' content digests -- so
    an auditor can trace a generated artifact back to the model version
    and the prompt digest. ``gov/decision_bom.py`` validates the shape
    and re-derives ``manifest_digest`` from the supplied manifest body
    on the audit path.
    """
    if not _is_hex64(manifest_digest_value):
        raise C2PAManifestError(
            "manifest_digest must be 64-char lowercase hex")
    if isinstance(chain_length, bool) or not isinstance(chain_length, int) \
            or chain_length < 1:
        raise C2PAManifestError(
            "chain_length must be a positive int, got %r" % (chain_length,))
    if not isinstance(root_ingredient_digests, list):
        raise C2PAManifestError("root_ingredient_digests must be a list")
    for i, d in enumerate(root_ingredient_digests):
        if not _is_hex64(d):
            raise C2PAManifestError(
                "root_ingredient_digests[%d] must be 64-char lowercase "
                "hex" % i)
    return {"manifest_digest": manifest_digest_value,
            "chain_length": chain_length,
            "root_ingredient_digests": list(root_ingredient_digests)}
