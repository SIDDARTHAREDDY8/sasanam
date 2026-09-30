"""AAuth R3 vocabulary grant tokens (wave-239).

Adapted from the authorization-resource negotiation pattern described in
``draft-hardt-aauth-r3-00`` (prose re-derived; the draft source repository
carries NOASSERTION licensing, so nothing is quoted and no code is reused).
The idea: grant tokens carry operations in a CLOSED vocabulary format --
vocabulary-typed operation records -- instead of free-text scopes.

The token carries R3 claims:

* ``r3_uri`` (REQUIRED) -- the URI of the R3 document in effect at approval
  time;
* ``r3_s256`` (REQUIRED) -- the SHA-256 of that R3 document, base64url
  without padding. The hash is the document's identity, not the URI: the
  issuer MUST reject on hash mismatch.
* ``r3_grant_hash`` (REQUIRED) -- the SHA-256 of the issued
  (``r3_granted``, ``r3_per_call``) lists, base64url without padding.
  This pins the issuer's actual approval: a narrowed grant cannot be
  silently re-widened by the bearer, because the grant lists are
  content-bound, not trusted bearer state.
* ``r3_granted`` (REQUIRED) -- operations the issuer fully authorized; the
  resource serves these immediately.
* ``r3_per_call`` (OPTIONAL) -- operations authorized in principle but
  requiring a per-call challenge on the concrete parameters the agent
  supplies. Both lists use the same vocabulary-specific operation format
  as the R3 document itself.

Resource enforcement (no token introspection, no R3 fetch at enforcement
time): match in ``r3_granted`` -> SERVE; match in ``r3_per_call`` ->
CHALLENGE (build a per-call proposal for the exact call); no match ->
refuse ``r3-no-match`` (the reject decision).

Per-call proposal: an R3 document scoped to a single invocation, same
structure and same content-addressing. The per-call token pins the
proposal's hash; the challenge succeeds only when the call presented at
challenge time is byte-equal to the proposal's operation. Parameters
edited after content-addressing refuse ``r3-per-call-binding-broken`` --
approval binds the exact call that was proposed, never edited params.

The issuer MAY narrow the grant to fewer operations than the R3 document
defines; granting MORE than the document defines refuses
``r3-grant-beyond-document``.

The audit seam: :func:`audit_provenance` returns ``r3_uri`` + ``r3_s256``
-- permanent, verifiable provenance of what the token was approved
against. Callers attach this to their audit records.

The machine refusals, all vocabulary-bound to ``gov/decision_codes.py``:

- ``r3-malformed`` -- the token, document, or proposal is the wrong shape
  (missing r3_uri/r3_s256, wrong types, empty op lists where non-empty
  is required). Shape violations are refusals, never silent skips.
- ``r3-vocabulary-unknown`` -- a vocabulary URI the consumer does not
  register. Closed vocabulary means unknown vocabularies refuse.
- ``r3-unknown-operation`` -- an operation that is not well-formed in the
  vocabulary (unknown field, missing required field, non-string value).
  The unknown operation never reaches a resource.
- ``r3-s256-mismatch`` -- the token's pinned hash does not match the
  recomputed hash of the presented R3 document: the approval-time
  binding is broken.
- ``r3-grant-hash-mismatch`` -- the token's ``r3_granted``/``r3_per_call``
  lists were edited after issuance: the pinned grant hash does not
  match the recomputed hash of the presented lists. Bearer widening of
  a narrowed grant refuses here.
- ``r3-grant-beyond-document`` -- the grant authorizes an operation the
  R3 document itself does not define.
- ``r3-no-match`` -- the operation matches nothing in r3_granted or
  r3_per_call: the reject decision.
- ``r3-per-call-binding-broken`` -- the call presented at challenge time
  is not the exact call the per-call proposal content-addressed.

Stdlib only. Deterministic: no clock, no randomness, no I/O, no env reads.

What this does NOT do (honest boundaries):

- The vocabulary registry is in-memory and conservative: only the seven
  standard vocabulary URIs are registered, each with a narrow field
  schema. A vocabulary the deployment needs but we do not register
  refuses by design; extending the registry is a deployment decision,
  not a silent fallback.
- ``r3_s256`` binds the approval-time document bytes. It does not prove
  the document's CONTENTS were correct -- a vocabulary-typed wrong
  operation still serves. Vocabulary typing narrows what can be said,
  not whether what is said is wise.
- ``r3_grant_hash`` binds the issuer's actual approval -- the exact
  (``r3_granted``, ``r3_per_call``) lists -- but it is only checked by
  :func:`verify_token` at enforcement time. Any path that consults the
  token's grant lists WITHOUT verify_token would be reading bearer
  state; always verify first.
- ``r3_uri`` is an identifier, not a fetch instruction: verification
  never dereferences it. A token presented against a document it does
  not pin refuses as a hash mismatch even if the URI string matches.
"""

import base64
import hashlib
import json

R3_UNKNOWN_OPERATION = "r3-unknown-operation"
R3_VOCABULARY_UNKNOWN = "r3-vocabulary-unknown"
R3_MALFORMED = "r3-malformed"
R3_S256_MISMATCH = "r3-s256-mismatch"
R3_GRANT_HASH_MISMATCH = "r3-grant-hash-mismatch"
R3_PER_CALL_BINDING_BROKEN = "r3-per-call-binding-broken"
R3_NO_MATCH = "r3-no-match"
R3_GRANT_BEYOND_DOCUMENT = "r3-grant-beyond-document"

SERVE = "serve"
CHALLENGE = "challenge"


class R3Error(Exception):
    """Loud R3 token failure. ``code`` is the machine-readable failure
    mode."""

    def __init__(self, code, detail=""):
        super(R3Error, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


# The closed vocabulary registry. Each entry maps a vocabulary URI to the
# operation record schema: the fields an operation record may carry
# (``allowed``) and the fields it must carry (``required``). These are the
# seven standard vocabulary URIs; field schemas are deliberately narrow.
# Registries elsewhere may differ -- this module refuses anything outside
# what it registers, by design.
VOCABULARIES = {
    "urn:aauth:vocabulary:mcp": {
        "required": ("tool",),
        "allowed": ("tool", "arguments", "server"),
    },
    "urn:aauth:vocabulary:openapi": {
        "required": ("operation_id",),
        "allowed": ("operation_id", "path", "method"),
    },
    "urn:aauth:vocabulary:grpc": {
        "required": ("method",),
        "allowed": ("method", "service", "package"),
    },
    "urn:aauth:vocabulary:graphql": {
        "required": ("operation_name",),
        "allowed": ("operation_name", "operation_type", "query_hash"),
    },
    "urn:aauth:vocabulary:asyncapi": {
        "required": ("channel",),
        "allowed": ("channel", "operation", "message"),
    },
    "urn:aauth:vocabulary:wsdl": {
        "required": ("operation",),
        "allowed": ("operation", "port", "service"),
    },
    "urn:aauth:vocabulary:odata": {
        "required": ("entity_set",),
        "allowed": ("entity_set", "operation", "filter_hash"),
    },
}


def _canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _b64url_nopad(digest):
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def r3_s256_of(document):
    """The content address of an R3 document: SHA-256 over its canonical
    bytes, base64url without padding."""
    return _b64url_nopad(hashlib.sha256(_canonical_bytes(document)).digest())


def grant_hash_of(granted, per_call):
    """The content address of the authorization payload: SHA-256 over the
    canonical bytes of the issued (r3_granted, r3_per_call) lists,
    base64url without padding. This pins what the issuer APPROVED, so a
    bearer cannot widen a narrowed grant post-issuance: the lists are
    content-bound, not trusted bearer state."""
    payload = {"granted": list(granted), "per_call": list(per_call)}
    return _b64url_nopad(hashlib.sha256(_canonical_bytes(payload)).digest())


def _require_vocab(vocab_uri):
    schema = VOCABULARIES.get(vocab_uri)
    if schema is None:
        raise R3Error(R3_VOCABULARY_UNKNOWN,
                      "vocabulary %r is not registered" % (vocab_uri,))
    return schema


def validate_operation(vocab_uri, op):
    """Check one operation record against the vocabulary schema. Refuses
    ``r3-vocabulary-unknown`` / ``r3-unknown-operation`` / ``r3-malformed``.
    """
    if not isinstance(vocab_uri, str) or not vocab_uri:
        raise R3Error(R3_MALFORMED, "vocabulary URI must be a non-empty str")
    schema = _require_vocab(vocab_uri)
    if not isinstance(op, dict):
        raise R3Error(R3_UNKNOWN_OPERATION,
                      "operation must be a dict, got %s" % type(op).__name__)
    for field in op:
        if field not in schema["allowed"]:
            raise R3Error(R3_UNKNOWN_OPERATION,
                          "field %r not in vocabulary %r"
                          % (field, vocab_uri))
    for field in schema["required"]:
        if field not in op:
            raise R3Error(R3_UNKNOWN_OPERATION,
                          "required field %r missing for vocabulary %r"
                          % (field, vocab_uri))
    for field, value in op.items():
        if not isinstance(value, str) or not value:
            raise R3Error(R3_UNKNOWN_OPERATION,
                          "field %r must be a non-empty str" % (field,))
    return op


def validate_document(document):
    """Check an R3 document: ``{"vocabulary": uri, "operations": [...]}``.
    Refuses ``r3-malformed`` / ``r3-vocabulary-unknown`` /
    ``r3-unknown-operation``.
    """
    if not isinstance(document, dict):
        raise R3Error(R3_MALFORMED, "R3 document must be a dict")
    vocab_uri = document.get("vocabulary")
    ops = document.get("operations")
    if not isinstance(ops, list):
        raise R3Error(R3_MALFORMED, "R3 document needs an operations list")
    if not isinstance(vocab_uri, str) or not vocab_uri:
        raise R3Error(R3_MALFORMED, "vocabulary URI must be a non-empty str")
    _require_vocab(vocab_uri)  # closed vocabulary: checked even for no ops
    if set(document) != {"vocabulary", "operations"}:
        raise R3Error(R3_MALFORMED, "R3 document carries unknown members")
    for op in ops:
        validate_operation(vocab_uri, op)
    return document


def _check_subset(document_ops, granted, label):
    doc_set = set(_canonical_bytes(op) for op in document_ops)
    for op in granted:
        if _canonical_bytes(op) not in doc_set:
            raise R3Error(R3_GRANT_BEYOND_DOCUMENT,
                          "%s grants an operation the R3 document does not "
                          "define" % (label,))


def _check_token_shape(token):
    if not isinstance(token, dict):
        raise R3Error(R3_MALFORMED, "token must be a dict")
    if not isinstance(token.get("r3_uri"), str) or not token.get("r3_uri"):
        raise R3Error(R3_MALFORMED, "token needs a non-empty r3_uri")
    if not isinstance(token.get("r3_s256"), str) or not token.get("r3_s256"):
        raise R3Error(R3_MALFORMED, "token needs a non-empty r3_s256")
    if (not isinstance(token.get("r3_grant_hash"), str)
            or not token.get("r3_grant_hash")):
        raise R3Error(R3_MALFORMED, "token needs a non-empty r3_grant_hash")
    if not isinstance(token.get("r3_granted"), list):
        raise R3Error(R3_MALFORMED, "token needs an r3_granted list")
    per_call = token.get("r3_per_call", [])
    if not isinstance(per_call, list):
        raise R3Error(R3_MALFORMED, "r3_per_call must be a list")
    if set(token) - {"r3_uri", "r3_s256", "r3_grant_hash",
                     "r3_granted", "r3_per_call"}:
        raise R3Error(R3_MALFORMED, "token carries unknown claims")
    return (token["r3_uri"], token["r3_s256"], token["r3_grant_hash"],
            token["r3_granted"], per_call)


def issue_grant_token(document, granted, per_call=None, r3_uri=None):
    """Mint a grant token against an R3 document. The token pins the
    document's content address; every granted/per-call operation must be
    vocabulary-typed and a subset of the document's operations (the issuer
    may narrow, never widen). Refuses ``r3-malformed`` /
    ``r3-vocabulary-unknown`` / ``r3-unknown-operation`` /
    ``r3-grant-beyond-document``.
    """
    document = validate_document(document)
    vocab_uri = document["vocabulary"]
    granted = list(granted) if granted is not None else []
    per_call = list(per_call) if per_call is not None else []
    for op in granted + per_call:
        validate_operation(vocab_uri, op)
    _check_subset(document["operations"], granted, "r3_granted")
    _check_subset(document["operations"], per_call, "r3_per_call")
    if not isinstance(r3_uri, str) or not r3_uri:
        raise R3Error(R3_MALFORMED, "r3_uri is REQUIRED and must be non-empty")
    return {
        "r3_uri": r3_uri,
        "r3_s256": r3_s256_of(document),
        "r3_grant_hash": grant_hash_of(granted, per_call),
        "r3_granted": granted,
        "r3_per_call": per_call,
    }


def verify_token(token, document):
    """Verify a token against the presented R3 document: shape, then the
    pinned document hash (approval-time binding), then the pinned grant
    hash (the issuer's actual approval -- bearer edits to the grant lists
    refuse), then vocabulary typing of every operation. Refuses
    ``r3-malformed`` / ``r3-s256-mismatch`` / ``r3-grant-hash-mismatch`` /
    ``r3-vocabulary-unknown`` / ``r3-unknown-operation``. Returns the
    checked (r3_uri, r3_s256, r3_grant_hash, granted, per_call) tuple.
    """
    document = validate_document(document)
    r3_uri, pinned, grant_pinned, granted, per_call = _check_token_shape(
        token)
    if pinned != r3_s256_of(document):
        raise R3Error(R3_S256_MISMATCH,
                      "token pins a different R3 document than presented")
    if grant_pinned != grant_hash_of(granted, per_call):
        raise R3Error(R3_GRANT_HASH_MISMATCH,
                      "token grant lists were edited after issuance")
    vocab_uri = document["vocabulary"]
    for op in granted + per_call:
        validate_operation(vocab_uri, op)
    return r3_uri, pinned, grant_pinned, granted, per_call


def check_access(token, document, op):
    """Resource enforcement: match in r3_granted -> SERVE; match in
    r3_per_call -> CHALLENGE; no match -> refuse ``r3-no-match``. No token
    introspection, no R3 fetch: the document is caller-supplied and
    hash-bound by verify_token.
    """
    if not isinstance(op, dict):
        raise R3Error(R3_MALFORMED, "operation must be a dict")
    _, _, _, granted, per_call = verify_token(token, document)
    validate_operation(document["vocabulary"], op)
    probe = _canonical_bytes(op)
    if any(_canonical_bytes(g) == probe for g in granted):
        return SERVE
    if any(_canonical_bytes(p) == probe for p in per_call):
        return CHALLENGE
    raise R3Error(R3_NO_MATCH,
                  "operation matches neither r3_granted nor r3_per_call")


def issue_per_call_token(document, proposed_call, r3_uri=None):
    """Mint a per-call token for the exact proposed call. The token pins
    the content address of a single-invocation proposal document; the
    proposal binds the approval to the call that was proposed.
    """
    document = validate_document(document)
    vocab_uri = document["vocabulary"]
    validate_operation(vocab_uri, proposed_call)
    if not isinstance(r3_uri, str) or not r3_uri:
        raise R3Error(R3_MALFORMED, "r3_uri is REQUIRED and must be non-empty")
    proposal = {"vocabulary": vocab_uri, "operations": [proposed_call]}
    per_call = [proposed_call]
    return {
        "r3_uri": r3_uri,
        "r3_s256": r3_s256_of(proposal),
        "r3_grant_hash": grant_hash_of([], per_call),
        "r3_granted": [],
        "r3_per_call": per_call,
    }


def challenge_per_call(token, proposal_document, call):
    """Complete the per-call challenge: the token must pin the presented
    proposal document (hash mismatch refuses ``r3-s256-mismatch``), and the
    call presented at challenge time must be byte-equal to the proposal's
    operation (edited params refuse ``r3-per-call-binding-broken``).
    Returns SERVE on an exact bind.
    """
    proposal = validate_document(proposal_document)
    if len(proposal["operations"]) != 1:
        raise R3Error(R3_MALFORMED,
                      "per-call proposal must scope exactly one operation")
    _r3_uri, _pinned, _grant_pinned, _granted, _per_call = verify_token(
        token, proposal)
    expected = proposal["operations"][0]
    if _canonical_bytes(call) != _canonical_bytes(expected):
        raise R3Error(R3_PER_CALL_BINDING_BROKEN,
                      "challenged call differs from the content-addressed "
                      "proposal")
    return SERVE


def audit_provenance(token):
    """Audit-log provenance for a token: r3_uri + r3_s256 -- permanent,
    verifiable evidence of what the token was approved against.
    """
    if not isinstance(token, dict):
        raise R3Error(R3_MALFORMED, "token must be a dict")
    r3_uri, pinned = token.get("r3_uri"), token.get("r3_s256")
    if not isinstance(r3_uri, str) or not r3_uri:
        raise R3Error(R3_MALFORMED, "token needs a non-empty r3_uri")
    if not isinstance(pinned, str) or not pinned:
        raise R3Error(R3_MALFORMED, "token needs a non-empty r3_s256")
    return {"r3_uri": r3_uri, "r3_s256": pinned}
