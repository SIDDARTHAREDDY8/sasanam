"""Wave-297: approval-request schema (GerritCodeReview/gerrit STEAL +
spinnaker manualJudgment STEAL, Apache-2.0, mechanism only, stdlib only).

Standing design rule: "An approval is a signed, time-boxed,
quorum-counted vote on a digest -- never a button, never a silence,
never a snapshot."

An ``ApprovalRequest`` is a bounded, frozen, signed declaration of
WHAT the human is being asked to approve. It carries:

* the **action digest** -- what is being approved, digest-bound, never
  a snapshot reference (Gerrit's version-reset: re-plan => the digest
  changes => the request no longer matches);
* the **requesting agent's identity** (agent_id + principal + the
  requester's ed25519 pubkey, which signs the request);
* the **full context digests** -- named digests of inputs, policy
  version, evidence (digests, never raw values);
* an **expiry** -- ``issued_at`` + ``ttl_seconds``; silence refuses,
  never consents (Spinnaker ``stageTimeoutMs``);
* a **typed approver-data schema** -- the validated inputs the
  approver must supply (Spinnaker ``judgmentInputs``), distinct from
  authority;
* the **requester's signature** over the canonical request body.

``issue()`` validates shape and freezes (any post-issue mutation
breaks the signature). ``verify_request()`` checks shape, digest
completeness, request/action binding, expiry at every use (pre-decay
fail-closed), and the signature. All refusals are coded:

* ``approval-request-expired`` -- the request's time box elapsed;
  silence refuses.
* ``approval-request-invalid`` -- malformed shape, bad schema, or a
  request from the future.
* ``approval-request-digest-missing`` -- missing/incomplete digest
  binding (empty context digests, malformed action digest, or the
  presented action digest is not the one this request authorizes).
* ``approval-request-forgery`` -- bad signature, mutated body, or a
  requester-pubkey pin mismatch.

The vote side (quorum labels, vetoes) is a separate lane; this module
is the request schema + verification + expiry discipline only.
Composition: ``gov.approvals.ApprovalQueue.queue(...,
approval_request=...)`` stamps an issued request on the record
(MAC-bound) and re-verifies it -- signature, action binding, expiry --
at every ``decide()``.

$0 spend, synthetic/local, deterministic. Stdlib only.
"""

import hashlib
import json
import time

from . import ed25519 as _ed25519

SCHEMA = "approval-request/v1"

EXPIRED = "approval-request-expired"
INVALID = "approval-request-invalid"
DIGEST_MISSING = "approval-request-digest-missing"
FORGERY = "approval-request-forgery"

# Bounds: the request is a declaration, not a document.
MAX_CONTEXT_DIGESTS = 32
MAX_DIGEST_NAME_LEN = 64
MAX_SCHEMA_FIELDS = 16
MAX_FIELD_NAME_LEN = 64
MAX_ENUM_VALUES = 8
MAX_STR_LEN = 256
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 30 * 24 * 3600  # 30 days: a time box, not a lease

_SCHEMA_FIELD_TYPES = ("string", "integer", "number", "boolean", "enum")


class ApprovalRequestError(Exception):
    """Code-first exception for approval-request failures."""

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


def _fail(code, detail):
    raise ApprovalRequestError(detail, code=code)


def _canonical(obj):
    """Canonical bytes for digesting/signing. Fail-closed on
    pathological shapes (circular refs, mixed-type keys) -- never
    hashes garbage."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True, default=str).encode("utf-8")
    except (ValueError, TypeError) as e:
        _fail(INVALID, "not canonicalizable: %s" % (e,))


def _check_str(value, what, max_len=MAX_STR_LEN, allow_empty=False):
    if not isinstance(value, str) or (not allow_empty and not value):
        _fail(INVALID, "%s must be a non-empty string; got %r"
              % (what, value,))
    if len(value) > max_len:
        _fail(INVALID, "%s exceeds %d chars" % (what, max_len))
    return value


def _check_hex_digest(value, what):
    """A sha256 digest: 64 lowercase hex chars. Missing or malformed
    digest binding is DIGEST_MISSING, not INVALID -- the request does
    not completely bind its subject."""
    if not isinstance(value, str):
        _fail(INVALID, "%s must be a string; got %r" % (what, type(value),))
    if len(value) != 64:
        _fail(DIGEST_MISSING,
              "%s must be a 64-char hex digest; got %r" % (what, value,))
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(DIGEST_MISSING, "%s is not hex: %r" % (what, value,))
    if raw.hex() != value:
        # bytes.fromhex tolerates uppercase and whitespace; the
        # canonical form is lowercase hex with no separators.
        _fail(DIGEST_MISSING,
              "%s must be lowercase hex; got %r" % (what, value,))
    return value


def _check_pubkey_hex(value, what):
    _check_str(value, what, max_len=64)
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(INVALID, "%s is not hex: %r" % (what, value,))
    if len(raw) != 32:
        _fail(INVALID, "%s must be a 32-byte ed25519 pubkey; got %d bytes"
              % (what, len(raw)))
    return value


def _check_seed(seed):
    if not isinstance(seed, (bytes, bytearray)) or len(bytes(seed)) != 32:
        _fail(INVALID, "requester_seed must be 32 bytes; got %r"
              % (type(seed),))
    return bytes(seed)


def _check_context_digests(digests):
    if not isinstance(digests, dict) or not digests:
        _fail(DIGEST_MISSING,
              "context_digests must be a non-empty dict of name->digest; "
              "got %r" % (type(digests),))
    if len(digests) > MAX_CONTEXT_DIGESTS:
        _fail(DIGEST_MISSING, "context_digests exceeds %d entries"
              % MAX_CONTEXT_DIGESTS)
    out = {}
    for name, digest in digests.items():
        if not isinstance(name, str) or not name:
            _fail(DIGEST_MISSING,
                  "context digest names must be non-empty strings; got %r"
                  % (name,))
        if len(name) > MAX_DIGEST_NAME_LEN:
            _fail(DIGEST_MISSING, "context digest name exceeds %d chars"
                  % MAX_DIGEST_NAME_LEN)
        out[name] = _check_hex_digest(digest, "context_digests[%r]" % name)
    return out


def _check_approver_schema(schema):
    """Typed approver-data schema: the validated inputs the approver
    must supply. A list of {name, type, required, values?}; ``enum``
    requires a non-empty values list. Strict: unknown keys refused."""
    if not isinstance(schema, list):
        _fail(INVALID, "approver_schema must be a list; got %r"
              % (type(schema),))
    if len(schema) > MAX_SCHEMA_FIELDS:
        _fail(INVALID, "approver_schema exceeds %d fields"
              % MAX_SCHEMA_FIELDS)
    fields = []
    seen = set()
    for i, field in enumerate(schema):
        where = "approver_schema[%d]" % i
        if not isinstance(field, dict):
            _fail(INVALID, "%s must be a dict; got %r" % (where, field))
        allowed = {"name", "type", "required", "values"}
        for key in field:
            if key not in allowed:
                _fail(INVALID, "%s: unknown key %r" % (where, key))
        name = field.get("name")
        if not isinstance(name, str) or not name:
            _fail(INVALID, "%s.name must be a non-empty string" % where)
        if len(name) > MAX_FIELD_NAME_LEN:
            _fail(INVALID, "%s.name exceeds %d chars"
                  % (where, MAX_FIELD_NAME_LEN))
        if name in seen:
            _fail(INVALID, "%s: duplicate field name %r" % (where, name))
        seen.add(name)
        ftype = field.get("type")
        if ftype not in _SCHEMA_FIELD_TYPES:
            _fail(INVALID, "%s.type must be one of %s; got %r"
                  % (where, _SCHEMA_FIELD_TYPES, ftype))
        required = field.get("required", False)
        if not isinstance(required, bool):
            _fail(INVALID, "%s.required must be a bool; got %r"
                  % (where, required))
        values = field.get("values")
        if ftype == "enum":
            if (not isinstance(values, list) or not values
                    or len(values) > MAX_ENUM_VALUES):
                _fail(INVALID,
                      "%s: enum requires a non-empty values list (<=%d)"
                      % (where, MAX_ENUM_VALUES))
            for v in values:
                if not isinstance(v, str) or not v or len(v) > MAX_STR_LEN:
                    _fail(INVALID, "%s: enum values must be non-empty "
                          "strings <=%d chars" % (where, MAX_STR_LEN))
        elif values is not None:
            _fail(INVALID, "%s: values only allowed for enum fields"
                  % where)
        entry = {"name": name, "type": ftype, "required": required}
        if ftype == "enum":
            entry["values"] = list(values)
        fields.append(entry)
    return fields


def validate_approver_data(schema_fields, data):
    """Validate approver-supplied data against the request's typed
    schema. Returns the validated dict. Unknown fields, missing
    required fields, type violations, and off-enum values refuse
    coded INVALID -- the data is distinct from authority."""
    fields = _check_approver_schema(schema_fields)
    if not isinstance(data, dict):
        _fail(INVALID, "approver data must be a dict; got %r"
              % (type(data),))
    known = {f["name"]: f for f in fields}
    for key in data:
        if key not in known:
            _fail(INVALID, "approver data has unknown field %r" % (key,))
    out = {}
    for f in fields:
        name, ftype, required = f["name"], f["type"], f["required"]
        if name not in data:
            if required:
                _fail(INVALID, "approver data missing required field %r"
                      % (name,))
            continue
        value = data[name]
        if ftype == "string":
            if not isinstance(value, str):
                _fail(INVALID, "field %r must be a string" % (name,))
        elif ftype == "boolean":
            if not isinstance(value, bool):
                _fail(INVALID, "field %r must be a boolean" % (name,))
        elif ftype == "integer":
            if not isinstance(value, int) or isinstance(value, bool):
                _fail(INVALID, "field %r must be an integer" % (name,))
        elif ftype == "number":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                _fail(INVALID, "field %r must be a number" % (name,))
        elif ftype == "enum":
            if value not in f["values"]:
                _fail(INVALID, "field %r must be one of %r; got %r"
                      % (name, f["values"], value))
        out[name] = value
    return out


def action_digest_for(action):
    """Canonical digest of the action being approved: {tool, args}.
    The request binds this digest; a re-planned action (any arg change)
    produces a different digest and the request no longer matches."""
    if not isinstance(action, dict):
        _fail(INVALID, "action must be a dict; got %r" % (type(action),))
    tool = action.get("tool")
    if not isinstance(tool, str) or not tool:
        _fail(INVALID, "action.tool must be a non-empty string")
    args = action.get("args", {})
    if not isinstance(args, dict):
        _fail(INVALID, "action.args must be a dict")
    return hashlib.sha256(_canonical({"tool": tool, "args": args})).hexdigest()


def issue(*, action_digest, requester_agent_id, requester_principal,
          requester_pubkey_hex, context_digests, approver_schema,
          ttl_seconds, issued_at=None, requester_seed):
    """Issue (declare + sign + freeze) an approval request. Returns the
    frozen envelope {"request": body, "signature": hex}. Any post-issue
    mutation breaks the signature (verify_request => forgery)."""
    seed = _check_seed(requester_seed)
    body = {
        "schema": SCHEMA,
        "action_digest": _check_hex_digest(action_digest, "action_digest"),
        "requester": {
            "agent_id": _check_str(requester_agent_id, "requester_agent_id"),
            "principal": _check_str(requester_principal,
                                    "requester_principal"),
            "pubkey_hex": _check_pubkey_hex(requester_pubkey_hex,
                                            "requester_pubkey_hex"),
        },
        "context_digests": _check_context_digests(context_digests),
        "approver_schema": _check_approver_schema(approver_schema),
        "issued_at": _check_issued_at(issued_at),
        "ttl_seconds": _check_ttl(ttl_seconds),
    }
    # Canonicalize before signing: a body that cannot round-trip
    # canonical bytes is not issuable.
    _canonical(body)
    if _ed25519.publickey(seed).hex() != body["requester"]["pubkey_hex"]:
        _fail(INVALID, "requester_seed does not match requester_pubkey_hex")
    signature = _ed25519.sign(seed, _canonical(body)).hex()
    return {"request": body, "signature": signature}


def _check_issued_at(issued_at):
    if issued_at is None:
        return int(time.time())
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        _fail(INVALID, "issued_at must be an int epoch; got %r"
              % (type(issued_at),))
    if issued_at < 0:
        _fail(INVALID, "issued_at must be non-negative")
    return issued_at


def _check_ttl(ttl_seconds):
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        _fail(INVALID, "ttl_seconds must be an int; got %r"
              % (type(ttl_seconds),))
    if not (MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS):
        _fail(INVALID, "ttl_seconds must be in [%d, %d]; got %d"
              % (MIN_TTL_SECONDS, MAX_TTL_SECONDS, ttl_seconds))
    return ttl_seconds


def _check_envelope_shape(envelope):
    if not isinstance(envelope, dict):
        _fail(INVALID, "envelope must be a dict; got %r"
              % (type(envelope),))
    body = envelope.get("request")
    sig = envelope.get("signature")
    if not isinstance(body, dict):
        _fail(INVALID, "envelope.request must be a dict")
    if not isinstance(sig, str) or not sig:
        _fail(INVALID, "envelope.signature must be a non-empty string")
    if set(envelope.keys()) - {"request", "signature"}:
        _fail(INVALID, "envelope has unknown keys: %r"
              % sorted(set(envelope.keys()) - {"request", "signature"}))
    return body, sig


def _check_body_shape(body):
    if body.get("schema") != SCHEMA:
        _fail(INVALID, "schema must be %r; got %r" % (SCHEMA,
                                                      body.get("schema")))
    allowed = {"schema", "action_digest", "requester", "context_digests",
               "approver_schema", "issued_at", "ttl_seconds"}
    for key in body:
        if key not in allowed:
            _fail(INVALID, "request body has unknown key %r" % (key,))
    for key in allowed:
        if key not in body:
            _fail(INVALID, "request body missing key %r" % (key,))
    _check_hex_digest(body["action_digest"], "action_digest")
    requester = body["requester"]
    if not isinstance(requester, dict):
        _fail(INVALID, "requester must be a dict")
    for key in ("agent_id", "principal", "pubkey_hex"):
        if key not in requester:
            _fail(INVALID, "requester missing %r" % (key,))
    _check_str(requester["agent_id"], "requester.agent_id")
    _check_str(requester["principal"], "requester.principal")
    _check_pubkey_hex(requester["pubkey_hex"], "requester.pubkey_hex")
    _check_context_digests(body["context_digests"])
    _check_approver_schema(body["approver_schema"])
    body["issued_at"] = _check_issued_at(body["issued_at"])
    body["ttl_seconds"] = _check_ttl(body["ttl_seconds"])
    # The body must canonicalize: a mutated-but-valid-shaped body
    # (e.g. injected circular ref) is not verifiable.
    _canonical(body)
    return body


def verify_request(envelope, *, expected_action_digest=None,
                   expected_requester_pubkey_hex=None, now=None):
    """Verify an approval request envelope. Returns the request body on
    success; raises coded :class:`ApprovalRequestError` otherwise.

    Checks, in order: shape, digest-binding completeness, action
    binding (Gerrit version-reset: a re-planned action digest does not
    match), requester-pubkey pin, expiry at every use (pre-decay
    fail-closed: silence refuses), then the signature. ``now`` is epoch
    seconds (defaults to wall clock); tests pass a fixed clock.
    """
    body, sig_hex = _check_envelope_shape(envelope)
    body = _check_body_shape(body)
    if expected_action_digest is not None:
        _check_hex_digest(expected_action_digest, "expected_action_digest")
        if body["action_digest"] != expected_action_digest:
            _fail(DIGEST_MISSING,
                  "request authorizes digest %s, not the presented %s; "
                  "re-plan => re-request" % (body["action_digest"],
                                              expected_action_digest))
    if expected_requester_pubkey_hex is not None:
        _check_pubkey_hex(expected_requester_pubkey_hex,
                          "expected_requester_pubkey_hex")
        if body["requester"]["pubkey_hex"] != expected_requester_pubkey_hex:
            _fail(FORGERY, "requester pubkey does not match the pinned key")
    at = int(time.time()) if now is None else now
    if not isinstance(at, int) or isinstance(at, bool):
        _fail(INVALID, "now must be an int epoch")
    if body["issued_at"] > at:
        _fail(INVALID, "request is not yet active (issued_at in the future)")
    if at >= body["issued_at"] + body["ttl_seconds"]:
        _fail(EXPIRED,
              "request expired: issued_at=%d ttl=%d now=%d; silence "
              "refuses -- re-issue" % (body["issued_at"],
                                       body["ttl_seconds"], at))
    try:
        sig = bytes.fromhex(sig_hex)
    except ValueError:
        _fail(FORGERY, "signature is not hex")
    # gov.ed25519.verify returns exact True/False: check it, never
    # truthiness, never assume it raises (wave-243 lesson).
    pub = bytes.fromhex(body["requester"]["pubkey_hex"])
    if _ed25519.verify(pub, _canonical(body), sig) is not True:
        _fail(FORGERY, "signature does not verify against the request body")
    return body


def matches_action(envelope, action_digest):
    """True iff the envelope is a valid, unexpired request that
    authorizes exactly ``action_digest``. Never raises: a non-match is
    False, not an exception (callers branch on it)."""
    try:
        verify_request(envelope, expected_action_digest=action_digest)
    except ApprovalRequestError:
        return False
    return True


def is_expired(envelope, now=None):
    """True iff the envelope's time box has elapsed. Shape errors are
    not expiry: an uninterpretable envelope is not 'expired', it is
    invalid -- so this raises INVALID on malformed envelopes rather
    than returning a misleading False."""
    body, _sig_hex = _check_envelope_shape(envelope)
    body = _check_body_shape(body)
    at = int(time.time()) if now is None else now
    if not isinstance(at, int) or isinstance(at, bool):
        _fail(INVALID, "now must be an int epoch")
    return at >= body["issued_at"] + body["ttl_seconds"]


def quorum_digest_input(envelope):
    """Project a request into gov.approval_quorum's digest shape.

    Wave-297 merge seam (the two modules were built in parallel lanes).
    The quorum binds votes to the canonical digest of::

        {"schema": "approval-request/v1", "request_id": <str>,
         "requester_id": <str>, "action_digest": <64 lowercase hex>,
         "expires_at": <int unix epoch>, "version": 1}

    This function derives that mapping from a signed request envelope
    (or a bare request body):

    * ``request_id`` -- sha256 of the canonical request body; unique
      per request content, so a re-plan (new digest) is a new request;
    * ``requester_id`` -- the requester's ``agent_id``;
    * ``expires_at`` -- ``issued_at + ttl_seconds`` (the quorum's
      expiry horizon is the request's own time box).

    The body SHAPE is validated fail-closed; the request's own
    signature is NOT re-verified here -- signature verification is
    ``verify_request()``'s job (the approval queue calls it at queue
    time and the decide path re-verifies). The quorum verifies votes,
    not requests; a digest of a forged request simply never matches
    an honestly-voted digest.
    """
    if isinstance(envelope, dict) and "request" in envelope:
        body = _check_envelope_shape(envelope)[0]
    elif isinstance(envelope, dict):
        body = envelope
    else:
        _fail(INVALID, "envelope must be a mapping; got %r"
              % (type(envelope),))
    body = _check_body_shape(body)
    requester = body["requester"]
    if not isinstance(requester, dict):
        _fail(INVALID, "requester must be a mapping")
    agent_id = requester.get("agent_id")
    if not isinstance(agent_id, str) or not agent_id:
        _fail(INVALID, "requester.agent_id must be a non-empty string")
    action_digest = _check_hex_digest(body["action_digest"], "action_digest")
    issued_at = body["issued_at"]
    ttl = body["ttl_seconds"]
    if (not isinstance(issued_at, int) or isinstance(issued_at, bool)
            or not isinstance(ttl, int) or isinstance(ttl, bool)):
        _fail(INVALID, "issued_at/ttl_seconds must be int epochs")
    return {
        "schema": SCHEMA,
        "request_id": hashlib.sha256(_canonical(body)).hexdigest(),
        "requester_id": agent_id,
        "action_digest": action_digest,
        "expires_at": issued_at + ttl,
        "version": 1,
    }
