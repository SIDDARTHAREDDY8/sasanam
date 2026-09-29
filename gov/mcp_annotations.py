"""Keyset-attested MCP ToolAnnotations registry.

The schema half of the modelcontextprotocol/python-sdk ADAPT verdict
(wave-194 prospectus): ``ToolAnnotations`` -- ``read_only_hint``,
``destructive_hint``, ``idempotent_hint``, ``open_world_hint`` -- as the
canonical declaration format for our MCP tool registry, plus the SDK's
own honest rule, which is the real product requirement:

    "Clients should never make tool use decisions based on
     ToolAnnotations received from untrusted servers."

Annotations are self-asserted by the tool server, so they are NEVER
trusted on the wire. Our registry ATTESTS them: an operator reviews a
tool's annotations and signs a per-``server::tool`` attestation statement
with the versioned keyset ceremony (the same machinery as
``gov.cosign_attest`` -- active versions mint, verify-only versions keep
old attestations verifiable, revoked versions refuse on the
authorization path). The authorization path treats un-attested
annotations as ABSENT: classification fails toward the conservative
reading (destructive assumed true, read-only assumed false -- the SDK
defaults), never toward the server's self-declaration.

Two consumers, deliberately separated:

* ADVISORY -- :func:`classify_tool`: given a verified registry, return
  the attested annotations for a pair, or the conservative defaults
  when the pair is un-attested. The policy layer can record this in the
  decision record. Advisory only: classification never upgrades a deny
  and never invents a refusal. CONSUMPTION CONTRACT: any policy rule
  that gates on an annotation being safe (e.g. "requires
  read_only_hint=true") must read it from :func:`classify_tool`, never
  from the wire -- un-attested tools classify destructive there, so
  such rules deny them by default. That is where the conservative
  semantics bite: the wire claim is simply not an input.

* AUTHORIZATION -- :func:`check_required_scopes`, wired into
  ``gov.authority_proof.check()``'s ``mcp_tools`` section: an attested
  entry may declare ``required_scopes`` (the
  ``RequireAuthMiddleware(required_scopes=[...])`` pattern from the
  SDK's bearer-auth middleware). When scopes are required, the caller's
  identity-token claim set (wave-192 ``token_claims``: ``iss``/``aud``/
  ``exp``/``agent_scope``) must validate AND name every required scope;
  otherwise the proof is ``exceeds_boundary`` (fail closed). Attestation
  can only tighten: a pair with no attestation has no required scopes,
  and the boundary allowlist remains the authorization decision.

Attestation layout (canonical JSON, UTF-8, sorted keys, no trailing
whitespace)::

    {"format": "sasanam-mcp-tool-annotations/v1",
     "pair": "files::read",
     "annotations": {"read_only_hint": true, "destructive_hint": false,
                     "idempotent_hint": true, "open_world_hint": false},
     "required_scopes": ["mcp:files:read"],
     "attested_by": {"purpose": "mcp-tool-annotation-attestation",
                     "keyset_key_id": "<8-byte hex>",
                     "keyset_version": 1,
                     "keyset_hash": "<sha256 of the keyset document as of
                                    the attesting version>"},
     "at": <unix seconds, int>,
     "envelope": {"sig_key_id": ..., "sig_key_version": 1,
                  "sig": "<hex ed25519 signature>"}}

The envelope signature covers the domain
``b"sasanam-mcp-tool-annotations/v1\\0"`` plus the canonical statement
(everything except ``envelope``). The verifying key is resolved via
``Keyset.find_verifying_key`` -- revoked versions refuse on the
standard path, verify-only versions verify; the forensics path
resolves revoked versions for attribution only.

``attested_by.keyset_hash`` pins the keyset document hash as of the
attesting version, rotation-stable via the rotation lineage (same
recipe as ``gov.cosign_attest.keyset_hash_at_version``).

What this module does NOT do (blunt residuals):

* It does not verify that attested annotations are TRUE. Attestation
  records that an operator reviewed the tool, not that the tool
  behaves. A lying server defeats any annotation scheme -- the
  registry answers "who attested this claim", not "is the claim true".
* The executor's pre-decision ``check()`` call sites do not yet pass
  the caller's verified token claims; the enforcement is live at the
  ``check()`` seam for callers that pass ``mcp_tool_registry`` +
  ``token_claims``. Executor plumbing is follow-on work.
* A registry is point-in-time: ``check()`` does not re-verify keyset
  status per call, so the operator must rebuild the registry after
  any keyset rotation/revocation (same freshness model as
  ``AuthorityBoundary`` itself).
* The ``forensics=True`` path on :func:`verify_tool_attestation` is
  attribution-only (which key attested this, post-incident). It is
  deliberately unavailable on :func:`build_tool_registry`: an
  enforcement registry must never admit a revoked attestation.
* Scope names live in one flat namespace; there is no scope
  hierarchy (``mcp:files:*`` does not imply ``mcp:files:read``).

Stdlib only. $0 spend. Synthetic/local testing.
"""

import json
import time

try:
    from . import ed25519 as _ed
except ImportError:  # standalone/offline: ed25519.py beside this file
    import ed25519 as _ed

try:
    from .keyset import (
        Keyset,
        KeysetError,
        keyset_signer_for_version,
    )
except ImportError:  # standalone/offline
    from keyset import (
        Keyset,
        KeysetError,
        keyset_signer_for_version,
    )

try:
    from .cosign_attest import keyset_hash_at_version
except ImportError:  # standalone/offline
    from cosign_attest import keyset_hash_at_version

try:
    from .decision_packet import check_token_claims
except ImportError:  # standalone/offline
    from decision_packet import check_token_claims

__all__ = [
    "ANNOTATION_FORMAT",
    "ANNOTATION_DOMAIN",
    "ATTESTATION_PURPOSE",
    "ANNOTATION_FIELDS",
    "CONSERVATIVE_ANNOTATIONS",
    "McpAnnotationError",
    "normalize_pair",
    "normalize_annotations",
    "normalize_scopes",
    "attest_tool_annotations",
    "verify_tool_attestation",
    "build_tool_registry",
    "classify_tool",
    "check_required_scopes",
    "scope_set",
]

ANNOTATION_FORMAT = "sasanam-mcp-tool-annotations/v1"
ANNOTATION_DOMAIN = b"sasanam-mcp-tool-annotations/v1\x00"
ATTESTATION_PURPOSE = "mcp-tool-annotation-attestation"

#: The ToolAnnotations field vocabulary, stolen from
#: modelcontextprotocol/python-sdk (MIT). All four are strict booleans
#: on the attested side -- the wire may omit them, the attestation may
#: not.
ANNOTATION_FIELDS = (
    "read_only_hint",
    "destructive_hint",
    "idempotent_hint",
    "open_world_hint",
)

#: The fail-toward classification for un-attested (or un-verifiable)
#: tools: destructive assumed true, read-only assumed false -- the SDK
#: defaults. An un-attested tool is never classified as safe.
CONSERVATIVE_ANNOTATIONS = {
    "read_only_hint": False,
    "destructive_hint": True,
    "idempotent_hint": False,
    "open_world_hint": True,
}

_STATEMENT_FIELDS = frozenset({
    "format", "pair", "annotations", "required_scopes",
    "attested_by", "at", "envelope",
})
_ATTESTED_BY_FIELDS = frozenset({
    "purpose", "keyset_key_id", "keyset_version", "keyset_hash",
})
_ENVELOPE_FIELDS = frozenset({"sig_key_id", "sig_key_version", "sig"})


class McpAnnotationError(Exception):
    """Raised when minting an attestation from bad inputs."""


def _canonical(obj):
    """Deterministic JSON for signing (same recipe as gov/keyset)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _require_int(value, what):
    if isinstance(value, bool) or not isinstance(value, int):
        raise McpAnnotationError("%s must be an integer, got %r"
                                 % (what, value))
    return value


def normalize_pair(raw):
    """Validate an exact ``server::tool`` pair identity.

    Same rules as the authority-boundary seam: non-empty parts, no NUL,
    no whitespace, no wildcards, and ``::`` only as the single pair
    separator (one pair can never masquerade as another). Raises
    :class:`McpAnnotationError` on any violation.
    """
    if not isinstance(raw, str) or not raw:
        raise McpAnnotationError(
            "tool pair must be a non-empty string, got %r" % (raw,))
    parts = raw.split("::")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise McpAnnotationError(
            "tool pair %r must be exactly 'server::tool'" % (raw,))
    for part, side in ((parts[0], "server"), (parts[1], "tool")):
        if "\x00" in part:
            raise McpAnnotationError(
                "tool pair %r %s part contains NUL" % (raw, side))
        if any(c.isspace() for c in part):
            raise McpAnnotationError(
                "tool pair %r %s part contains whitespace" % (raw, side))
        if "*" in part:
            raise McpAnnotationError(
                "tool pair %r %s part is a wildcard -- declare exact "
                "identities only" % (raw, side))
    return parts[0] + "::" + parts[1]


def normalize_annotations(raw):
    """Validate an attested annotation body: exactly the four fields,
    strict booleans (no coercion -- ``1``/``"true"`` are refused, per
    the typed-schema discipline). Returns a plain dict. Raises
    :class:`McpAnnotationError`.
    """
    if not isinstance(raw, dict):
        raise McpAnnotationError(
            "annotations must be a mapping, got %r" % (raw,))
    unknown = set(raw) - set(ANNOTATION_FIELDS)
    if unknown:
        raise McpAnnotationError(
            "annotations carry unknown fields: %s" % sorted(unknown))
    missing = set(ANNOTATION_FIELDS) - set(raw)
    if missing:
        raise McpAnnotationError(
            "annotations missing fields: %s" % sorted(missing))
    out = {}
    for field in ANNOTATION_FIELDS:
        val = raw[field]
        if not isinstance(val, bool):
            raise McpAnnotationError(
                "annotation %r must be a boolean, got %r" % (field, val))
        out[field] = val
    return out


def normalize_scopes(raw):
    """Validate a required-scopes list: list/tuple of non-empty,
    whitespace-free strings. Returns a sorted tuple (canonical --
    duplicates collapse). Raises :class:`McpAnnotationError`.
    """
    if not isinstance(raw, (list, tuple)):
        raise McpAnnotationError(
            "required_scopes must be a list, got %r" % (raw,))
    out = set()
    for scope in raw:
        if not isinstance(scope, str) or not scope:
            raise McpAnnotationError(
                "scope must be a non-empty string, got %r" % (scope,))
        if any(c.isspace() for c in scope):
            raise McpAnnotationError(
                "scope %r contains whitespace" % (scope,))
        out.add(scope)
    return tuple(sorted(out))


def attest_tool_annotations(keyset, pair, annotations, seed, *,
                            required_scopes=(), version=None, at=None):
    """Mint an attestation statement for one tool's annotations.

    The signing handle is minted via ``keyset_signer_for_version`` --
    a revoked or verify-only version's seed is refused here (retired
    material cannot mint new attestations), as is a seed that does not
    match the version's key. The keyset's purpose must be
    ``mcp-tool-annotation-attestation``.

    Returns the attestation statement as a dict (public material).
    """
    if not isinstance(keyset, Keyset):
        raise McpAnnotationError("keyset must be a gov.keyset.Keyset")
    if keyset.purpose != ATTESTATION_PURPOSE:
        raise McpAnnotationError(
            "keyset purpose %r cannot attest tool annotations (need %r)"
            % (keyset.purpose, ATTESTATION_PURPOSE))
    norm_pair = normalize_pair(pair)
    norm_ann = normalize_annotations(annotations)
    norm_scopes = normalize_scopes(required_scopes)
    if version is None:
        version = keyset.primary_version
    try:
        signer = keyset_signer_for_version(keyset, version, seed)
    except KeysetError as e:
        raise McpAnnotationError(
            "cannot mint an attestation signing handle: %s" % e)
    stamp = int(time.time()) if at is None else _require_int(at, "'at'")
    body = {
        "format": ANNOTATION_FORMAT,
        "pair": norm_pair,
        "annotations": norm_ann,
        "required_scopes": list(norm_scopes),
        "attested_by": {
            "purpose": keyset.purpose,
            "keyset_key_id": signer.key_id,
            "keyset_version": signer.key_version,
            "keyset_hash": keyset_hash_at_version(keyset,
                                                 signer.key_version),
        },
        "at": stamp,
    }
    sig = signer.sign(ANNOTATION_DOMAIN + _canonical(body)).hex()
    body["envelope"] = {
        "sig_key_id": signer.key_id,
        "sig_key_version": signer.key_version,
        "sig": sig,
    }
    return body


def _statement_error(reason):
    return False, reason


def _exact_fields(obj, fields, name):
    """Exact-field check for attestation structures.

    Returns an error string, or None when ``obj`` carries exactly
    ``fields``. Unknown and missing fields are both refusals -- the
    three attestation structures share this one check so the rule
    cannot drift between them.
    """
    unknown = set(obj) - fields
    if unknown:
        return "%s carries unknown fields: %s" % (name, sorted(unknown))
    missing = fields - set(obj)
    if missing:
        return "%s missing fields: %s" % (name, sorted(missing))
    return None


def verify_tool_attestation(attestation, keyset_doc, *, forensics=False):
    """Verify an attestation statement against a keyset document.

    Steps: structure (exact fields, exact format match) -> pair shape
    -> annotations shape (strict bools) -> scopes shape -> keyset parse
    + purpose + lineage -> attested_by/envelope consistency ->
    keyset-hash pin (historical document hash; rotation-stable via the
    lineage) -> envelope key resolution (``find_verifying_key``;
    revoked refuses unless ``forensics``) -> Ed25519 signature over
    domain + canonical statement.

    Returns ``(True, details)`` or ``(False, reason)``; never raises.
    """
    # -- structure -----------------------------------------------------
    if not isinstance(attestation, dict):
        return _statement_error("attestation is not a mapping")
    err = _exact_fields(attestation, _STATEMENT_FIELDS, "attestation")
    if err:
        return _statement_error(err)
    if attestation["format"] != ANNOTATION_FORMAT:
        return _statement_error(
            "attestation format %r is not %r (exact match required)"
            % (attestation.get("format"), ANNOTATION_FORMAT))
    try:
        pair = normalize_pair(attestation["pair"])
    except McpAnnotationError as e:
        return _statement_error("bad tool pair: %s" % e)
    try:
        annotations = normalize_annotations(attestation["annotations"])
    except McpAnnotationError as e:
        return _statement_error("bad annotations: %s" % e)
    try:
        scopes = normalize_scopes(attestation["required_scopes"])
    except McpAnnotationError as e:
        return _statement_error("bad required_scopes: %s" % e)
    try:
        _require_int(attestation["at"], "'at'")
    except McpAnnotationError as e:
        return _statement_error(str(e))

    att_by = attestation["attested_by"]
    if not isinstance(att_by, dict):
        return _statement_error("attested_by is not a mapping")
    err = _exact_fields(att_by, _ATTESTED_BY_FIELDS, "attested_by")
    if err:
        return _statement_error(err)
    if att_by["purpose"] != ATTESTATION_PURPOSE:
        return _statement_error(
            "attested_by purpose %r is not %r"
            % (att_by.get("purpose"), ATTESTATION_PURPOSE))
    if not isinstance(att_by["keyset_key_id"], str) \
            or not att_by["keyset_key_id"]:
        return _statement_error("attested_by.keyset_key_id is not text")
    av = att_by["keyset_version"]
    if isinstance(av, bool) or not isinstance(av, int) or av < 1:
        return _statement_error("attested_by.keyset_version is not a "
                                "positive integer")
    kh = att_by["keyset_hash"]
    if not isinstance(kh, str) or len(kh) != 64:
        return _statement_error("attested_by.keyset_hash is malformed")

    env = attestation["envelope"]
    if not isinstance(env, dict):
        return _statement_error("attestation envelope is not a mapping")
    err = _exact_fields(env, _ENVELOPE_FIELDS, "envelope")
    if err:
        return _statement_error(err)
    if env["sig_key_id"] != att_by["keyset_key_id"] \
            or env["sig_key_version"] != av:
        return _statement_error("envelope does not name the attested_by "
                                "key (key id / version mismatch)")

    # -- keyset ---------------------------------------------------------
    try:
        ks = Keyset.from_dict(keyset_doc)
    except KeysetError as e:
        return _statement_error("keyset document invalid: %s" % e)
    if ks.purpose != ATTESTATION_PURPOSE:
        return _statement_error(
            "keyset purpose %r cannot attest tool annotations" % ks.purpose)
    ok, err = ks.verify()
    if not ok:
        return _statement_error("keyset lineage invalid: %s" % err)

    # -- keyset-hash pin (rotation-stable via lineage) -------------------
    try:
        pinned = keyset_hash_at_version(ks, av)
    except KeysetError as e:
        return _statement_error("attested keyset version not in keyset: %s"
                                % e)
    if pinned != kh:
        return _statement_error(
            "attested_by.keyset_hash does not match the keyset document "
            "as of version %d (silent keyset substitution)" % av)

    # -- envelope key resolution ----------------------------------------
    if forensics:
        kv, lookup = ks.find_verifying_key_for_forensics(env)
    else:
        kv, lookup = ks.find_verifying_key(env)
    if kv is None:
        return _statement_error("envelope key lookup failed: %s" % lookup)
    if kv.version != av or kv.key_id != att_by["keyset_key_id"]:
        return _statement_error("resolved key does not match attested_by")

    # -- signature -------------------------------------------------------
    stmt = {k: v for k, v in attestation.items() if k != "envelope"}
    try:
        sig = bytes.fromhex(env["sig"])
    except (ValueError, TypeError):
        return _statement_error("envelope sig is not valid hex")
    if len(sig) != 64:
        return _statement_error("envelope sig is not 64 bytes")
    if not _ed.verify(kv.public_key, ANNOTATION_DOMAIN + _canonical(stmt),
                      sig):
        return _statement_error("attestation signature does not verify")

    return True, {"pair": pair,
                  "annotations": annotations,
                  "required_scopes": list(scopes),
                  "keyset_version": kv.version,
                  "status": kv.status,
                  "keyset_key_id": kv.key_id,
                  "lookup": lookup}


# ---------------------------------------------------------------------------
# Registry: the operator's attested view of tool annotations
# ---------------------------------------------------------------------------

def build_tool_registry(attestations, keyset_doc):
    """Build the attested tool registry from attestation statements.

    Every statement is verified on the standard path (never raises --
    failures are collected): revoked keyset versions REFUSE here,
    always. There is deliberately no forensics carve-out on this
    function -- a registry feeds the authorization path, and a revoked
    attestation admitted into it would be a trust elevation (its
    annotations honored instead of the conservative default).
    Post-incident attribution of revoked attestations goes through
    :func:`verify_tool_attestation` with ``forensics=True`` directly,
    never through a registry build.

    Returns ``(registry, refused)``: ``registry`` maps an exact
    ``server::tool`` pair to ``{"annotations": {...},
    "required_scopes": (...), "attested_by": {...}, "at": int}``;
    ``refused`` is a list of ``(index, reason)`` for statements that
    did not verify. A duplicate attestation for one pair is refused
    LOUD -- ambiguity in the registry is a fail-closed signal, not a
    tie to break silently (supersession is the operator issuing a new
    registry, not two live statements for one pair).

    Freshness contract: a registry is a point-in-time operator
    artifact, exactly like ``AuthorityBoundary``. ``check()`` does not
    re-verify keyset status per call, so after any keyset rotation or
    revocation the operator MUST rebuild the registry from the current
    keyset document; a registry built before a revocation keeps
    trusting the revoked attestation until rebuilt.
    """
    registry = {}
    refused = []
    if not isinstance(attestations, (list, tuple)):
        return {}, [(None, "attestations must be a list")]
    for idx, att in enumerate(attestations):
        ok, info = verify_tool_attestation(att, keyset_doc)
        if not ok:
            refused.append((idx, info))
            continue
        pair = info["pair"]
        if pair in registry:
            refused.append((idx, "duplicate attestation for pair %r: "
                                 "registry refuses ambiguity" % (pair,)))
            continue
        registry[pair] = {
            "annotations": dict(info["annotations"]),
            "required_scopes": tuple(info["required_scopes"]),
            "attested_by": {
                "keyset_key_id": info["keyset_key_id"],
                "keyset_version": info["keyset_version"],
                "status": info["status"],
            },
            "at": att["at"],
        }
    return registry, refused


# ---------------------------------------------------------------------------
# Advisory path: classification (never trusted from the wire)
# ---------------------------------------------------------------------------

def classify_tool(pair, registry, declared=None):
    """Classify one tool's annotations: attested or conservative.

    Returns ``(annotations_dict, source)`` with ``source`` one of
    ``"attested"`` / ``"conservative"``. The server's self-declared
    annotations (``declared``, the wire shape) are accepted for
    logging/telemetry but NEVER influence the classification -- that is
    the SDK's honest rule in code. A pair with a verified attestation
    in ``registry`` is classified by the attested annotations; every
    other pair -- un-attested, malformed, or registry-missing -- gets
    :data:`CONSERVATIVE_ANNOTATIONS` (destructive assumed true,
    read-only assumed false).

    Never raises: hostile input classifies conservative.
    """
    # `declared` is accepted and ignored by design; a non-mapping is
    # not even worth a complaint on the advisory path.
    if isinstance(registry, dict) and isinstance(pair, str):
        entry = registry.get(pair)
        if isinstance(entry, dict):
            ann = entry.get("annotations")
            try:
                norm = normalize_annotations(ann)
            except McpAnnotationError:
                norm = None
            if norm is not None:
                return norm, "attested"
    return dict(CONSERVATIVE_ANNOTATIONS), "conservative"


# ---------------------------------------------------------------------------
# Authorization path: required-scope enforcement
# ---------------------------------------------------------------------------

def scope_set(agent_scope):
    """Parse the token's ``agent_scope`` claim into a scope set.

    The claim is a whitespace-separated scope list (OAuth convention);
    returns the set of scope tokens. Never raises.
    """
    if not isinstance(agent_scope, str):
        return set()
    return set(agent_scope.split())


def check_required_scopes(pair, registry, token_claims):
    """Enforce attested required scopes for one tool pair.

    Returns ``(True, "ok")`` or ``(False, reason)``; never raises.

    * pair not attested (or no scopes required) -> ``(True, ...)``:
      attestation can only tighten, never invents requirements.
    * scopes required but no ``token_claims`` presented -> ``(False,
      ...)`` (fail closed).
    * claims presented -> validated by
      ``decision_packet.check_token_claims`` (``iss``/``aud``/``exp``
      policy); invalid or expired claims fail closed.
    * every required scope must be present in the claim's
      ``agent_scope`` set; a missing scope fails closed and names the
      missing scope(s).
    """
    if not isinstance(registry, dict):
        return False, "mcp tool registry is not a mapping"
    if not isinstance(pair, str) or pair not in registry:
        return True, "ok: pair not attested, no scopes required"
    entry = registry[pair]
    if not isinstance(entry, dict):
        return False, "registry entry for %r is malformed" % (pair,)
    required = entry.get("required_scopes", ())
    if not isinstance(required, (list, tuple)) or any(
            not isinstance(s, str) for s in required):
        return False, "registry entry for %r has malformed " \
                      "required_scopes" % (pair,)
    required = tuple(required)
    if not required:
        return True, "ok: no scopes required"
    if token_claims is None:
        return False, ("tool %r requires scopes %r but no identity "
                       "token claims were presented" % (pair, required))
    ok, why = check_token_claims(token_claims)
    if not ok:
        return False, "identity token claims invalid: %s" % (why,)
    have = scope_set(token_claims.get("agent_scope"))
    missing = [s for s in required if s not in have]
    if missing:
        return False, ("missing required scope(s) for %r: %r "
                       "(agent_scope names %r)"
                       % (pair, missing, sorted(have)))
    return True, "ok"
