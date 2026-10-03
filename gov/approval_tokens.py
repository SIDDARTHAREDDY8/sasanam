"""Wave-313 lane B: capability-bound, argument-bound approval tokens.

Row 7 build-order step 3 (compositional defense). An approval token is
a sealed, single-use, time-boxed credential minted at decision time
that binds BOTH the authorized capability (which tool/operation) AND
the authorized arguments (exact values or a declared argument schema).

Why this exists: the trajectory-risk accumulator (wave-312, Row 7 step
2) measures that benign egress and harmful egress have the same shape
-- "email someone a body" scores HIGH either way. Only a binding made
by the human at decision time can tell them apart: a token minted for
``send_email(to="colleague", ...)`` never authorizes
``send_email(to="attacker", ...)``, and a token minted for one tool
never authorizes another. A decomposed trajectory where step 1 is
approved benign and step 3 tries to reuse the token for a harmful
variant is refused at verification -- the compositional gap the
decomp corpus (wave-310) measures.

Token structure: ``{v, capability, argument_binding, issuer,
issued_at, expires_at, nonce, key_epoch, mac}``. The seal is
HMAC-SHA256 under the active log HMAC key (the same key ceremony as
the approval-record MAC, F34) with the key epoch bound in and a
domain separator -- no new crypto is invented. Verification is
fail-closed and ordered cheap-to-expensive: shape, seal, expiry,
capability, arguments, replay. Every refusal is a coded
``ApprovalTokenError`` (``approval-token-*`` vocabulary, registered
in the decision-code taxonomy).

Replay: a token authorizes at most one execution. ``verify_token``
checks a caller-supplied ``TokenConsumeStore`` for the nonce but does
NOT consume it -- consumption is a separate step
(``TokenConsumeStore.consume``) so a caller can verify first and
consume only on the durable-claim path (the approved sweep consumes
after ``mark_executed``; a refused-later record keeps its token
unconsumed and retriable). The store is process-local in-memory;
cross-process at-most-once rides the approval queue lock plus the
record-executed marking, exactly like every other sweep check.

Honest boundary (threat model): the token seal and the approval
record MAC share the log HMAC key, so at the wired sweep seam the
token is an independent binding check, NOT key-compromise resistance
-- a key-holder could mint a conforming token directly. Its
compositional value is against decomposed reuse: a token
legitimately minted for a benign step cannot authorize a harmful
variant step, and the check is independent of the record MAC so a
record-level binding bug does not collapse both. The full payoff
comes when the token travels as a standalone artifact, decoupled
from the record (later Row-7 steps).

This module never executes anything. Stdlib only.
"""

import hashlib
import hmac
import json
import secrets
import time

try:
    from .log import _active_key
    from .egress_ledger import _ledger_keyring
    from . import decision_codes as _dc
except ImportError:  # standalone: sibling modules beside this file
    from log import _active_key
    from egress_ledger import _ledger_keyring
    import decision_codes as _dc

TOKEN_VERSION = 1
_MAC_DOMAIN = b"approval-token-v1:"

MALFORMED = "approval-token-malformed"
TAMPERED = "approval-token-tampered"
EXPIRED = "approval-token-expired"
CAPABILITY_MISMATCH = "approval-token-capability-mismatch"
ARGUMENT_MISMATCH = "approval-token-argument-mismatch"
REPLAYED = "approval-token-replayed"

# The token is a declaration, not a document.
MAX_STR_LEN = 256
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 30 * 24 * 3600  # 30 days: a time box, not a lease
MAX_SCHEMA_KEYS = 32
MAX_ENUM_VALUES = 64

_REQUIRED_FIELDS = ("v", "capability", "argument_binding", "issuer",
                    "issued_at", "expires_at", "nonce", "key_epoch", "mac")


class ApprovalTokenError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(ApprovalTokenError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _fail(code, detail):
    raise ApprovalTokenError(code, detail)


def _canonical(obj):
    """Canonical bytes for sealing/comparison. Only JSON-native values
    are sealable -- anything else is malformed, never silently
    coerced (a coercion could bind two different values to one seal)."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as e:
        _fail(MALFORMED, "not canonicalizable: %s" % (e,))


def _check_json_native(value, what):
    """Reject non-JSON-native values (sets, tuples, objects, non-finite
    floats). Fail-closed at issue: an unbindable value cannot ride a
    token."""
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if value != value or abs(value) == float("inf"):
            _fail(MALFORMED, "%s: non-finite float is not bindable" % what)
        return
    if isinstance(value, list):
        for i, v in enumerate(value):
            _check_json_native(v, "%s[%d]" % (what, i))
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                _fail(MALFORMED,
                      "%s: argument keys must be strings, got %r"
                      % (what, k))
            _check_json_native(v, "%s[%r]" % (what, k))
        return
    _fail(MALFORMED, "%s: value of type %s is not JSON-native and "
                     "cannot be bound" % (what, type(value).__name__))


def _check_str(value, what):
    if not isinstance(value, str) or not value:
        _fail(MALFORMED, "%s must be a non-empty string; got %r"
              % (what, value))
    if len(value) > MAX_STR_LEN:
        _fail(MALFORMED, "%s exceeds %d chars" % (what, MAX_STR_LEN))
    return value


def _check_hex32(value, what):
    if not isinstance(value, str) or len(value) != 32:
        _fail(MALFORMED, "%s must be 32 hex chars; got %r" % (what, value))
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(MALFORMED, "%s is not hex: %r" % (what, value))
    if raw.hex() != value:
        _fail(MALFORMED, "%s must be lowercase hex; got %r" % (what, value))
    return value


def _check_binding(binding):
    """Validate and normalize an argument_binding. Two modes:

    * ``{"mode": "exact", "args": {...}}`` -- the presented args must
      canonical-equal the bound args. Any substitution, removal, or
      addition (widening) mismatches.
    * ``{"mode": "schema", "schema": {key: {"enum": [...]}}}`` -- the
      presented args must carry exactly the schema's keys (no widening
      past the declared surface) and each value must be one of the
      declared enum values (type-strict via canonical form).
    """
    if not isinstance(binding, dict):
        _fail(MALFORMED, "argument_binding must be a dict; got %r"
              % (type(binding),))
    mode = binding.get("mode")
    if mode == "exact":
        if set(binding.keys()) != {"mode", "args"}:
            _fail(MALFORMED,
                  "exact argument_binding has unknown keys: %r"
                  % sorted(set(binding.keys()) - {"mode", "args"}))
        args = binding.get("args")
        if not isinstance(args, dict):
            _fail(MALFORMED, "exact argument_binding args must be a dict")
        _check_json_native(args, "argument_binding.args")
        return {"mode": "exact", "args": args}
    if mode == "schema":
        if set(binding.keys()) != {"mode", "schema"}:
            _fail(MALFORMED,
                  "schema argument_binding has unknown keys: %r"
                  % sorted(set(binding.keys()) - {"mode", "schema"}))
        schema = binding.get("schema")
        if not isinstance(schema, dict) or not schema:
            _fail(MALFORMED,
                   "schema argument_binding schema must be a non-empty "
                   "dict")
        if len(schema) > MAX_SCHEMA_KEYS:
            _fail(MALFORMED, "schema exceeds %d keys" % MAX_SCHEMA_KEYS)
        out = {}
        for key, constraint in schema.items():
            _check_str(key, "schema key")
            if not isinstance(constraint, dict) or \
                    set(constraint.keys()) != {"enum"}:
                _fail(MALFORMED,
                      "schema[%r] must be {\"enum\": [...]}; got %r"
                      % (key, constraint))
            enum = constraint["enum"]
            if not isinstance(enum, list) or not enum:
                _fail(MALFORMED,
                      "schema[%r].enum must be a non-empty list" % key)
            if len(enum) > MAX_ENUM_VALUES:
                _fail(MALFORMED,
                      "schema[%r].enum exceeds %d values"
                      % (key, MAX_ENUM_VALUES))
            for v in enum:
                _check_json_native(v, "schema[%r].enum value" % key)
            out[key] = {"enum": list(enum)}
        return {"mode": "schema", "schema": out}
    _fail(MALFORMED, "argument_binding mode must be 'exact' or 'schema'; "
                     "got %r" % (mode,))


def _check_ttl(ttl_seconds):
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool):
        _fail(MALFORMED, "ttl_seconds must be an int; got %r"
              % (type(ttl_seconds),))
    if not (MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS):
        _fail(MALFORMED, "ttl_seconds must be in [%d, %d]; got %d"
              % (MIN_TTL_SECONDS, MAX_TTL_SECONDS, ttl_seconds))
    return ttl_seconds


def _check_issued_at(issued_at):
    if issued_at is None:
        return int(time.time())
    if not isinstance(issued_at, int) or isinstance(issued_at, bool):
        _fail(MALFORMED, "issued_at must be an int epoch; got %r"
              % (type(issued_at),))
    if issued_at < 0:
        _fail(MALFORMED, "issued_at must be non-negative")
    return issued_at


def _seal(body, key, key_epoch):
    msg = (_MAC_DOMAIN + key_epoch.encode("utf-8") + b"|"
           + _canonical(body))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def issue_token(capability, argument_binding, *, issuer, ttl_seconds,
                issued_at=None, nonce=None):
    """Mint a capability/argument-bound approval token. Never executes.

    The seal is HMAC-SHA256 under the active log HMAC key (the F34 key
    ceremony) with the key epoch bound in. The key is
    deployment-supplied and required: without it ``_active_key()``
    raises ``NoKeyConfiguredError`` -- fail closed, no fallback.
    Returns the token dict (JSON-native, frozen by the seal).
    """
    _check_str(capability, "capability")
    binding = _check_binding(argument_binding)
    _check_str(issuer, "issuer")
    _check_ttl(ttl_seconds)
    at = _check_issued_at(issued_at)
    if nonce is None:
        nonce = secrets.token_hex(16)
    _check_hex32(nonce, "nonce")
    key, key_epoch = _active_key()
    body = {
        "v": TOKEN_VERSION,
        "capability": capability,
        "argument_binding": binding,
        "issuer": issuer,
        "issued_at": at,
        "expires_at": at + ttl_seconds,
        "nonce": nonce,
        "key_epoch": key_epoch,
    }
    _canonical(body)  # the body must seal: fail closed if not
    token = dict(body)
    token["mac"] = _seal(body, key, key_epoch)
    return token


def _check_shape(token):
    if not isinstance(token, dict):
        _fail(MALFORMED, "token must be a dict; got %r"
              % (type(token),))
    for field in _REQUIRED_FIELDS:
        if field not in token:
            _fail(MALFORMED, "token missing field %r" % (field,))
    if set(token.keys()) != set(_REQUIRED_FIELDS):
        _fail(MALFORMED, "token has unknown fields: %r"
              % sorted(set(token.keys()) - set(_REQUIRED_FIELDS)))
    if token.get("v") != TOKEN_VERSION:
        _fail(MALFORMED, "unsupported token version %r"
              % (token.get("v"),))
    _check_str(token["capability"], "capability")
    _check_str(token["issuer"], "issuer")
    _check_hex32(token["nonce"], "nonce")
    _check_str(token["key_epoch"], "key_epoch")
    mac = token.get("mac")
    if not isinstance(mac, str) or len(mac) != 64:
        _fail(MALFORMED, "mac must be a 64-char hex digest")
    try:
        bytes.fromhex(mac)
    except ValueError:
        _fail(MALFORMED, "mac is not hex")
    for field in ("issued_at", "expires_at"):
        value = token.get(field)
        if not isinstance(value, int) or isinstance(value, bool) \
                or value < 0:
            _fail(MALFORMED, "%s must be a non-negative int epoch"
                  % field)
    if token["expires_at"] <= token["issued_at"]:
        _fail(MALFORMED, "expires_at must be after issued_at")
    # The binding sealed at issue was valid; a token that cannot even
    # be re-validated is not interpretable.
    _check_binding(token["argument_binding"])
    return token


def _seal_ok(token):
    """True when the seal recomputes under some keyring epoch."""
    body = {k: token[k] for k in _REQUIRED_FIELDS if k != "mac"}
    for key_epoch, key in _ledger_keyring().items():
        if key_epoch != token["key_epoch"]:
            continue
        if hmac.compare_digest(_seal(body, key, key_epoch), token["mac"]):
            return True
    return False


class TokenConsumeStore(object):
    """Process-local nonce consumption ledger.

    A token authorizes at most one execution: ``consume(nonce)``
    records the nonce and returns True; consuming an already-consumed
    nonce raises ``approval-token-replayed``. Single-process by
    design (the approved sweep's at-most-once across processes rides
    the queue lock plus the record-executed marking); a multi-process
    deployment that presents tokens at another seam must supply a
    shared store behind this interface.
    """

    def __init__(self):
        self._consumed = {}  # nonce -> consumed_at epoch

    def is_consumed(self, nonce):
        return nonce in self._consumed

    def snapshot(self):
        """A plain-dict copy of the consumed-nonce ledger: the durability
        seam. A deployment that must refuse replays across processes or
        runs persists this snapshot in its shared store and hydrates a
        fresh ``TokenConsumeStore`` from it (see ``restore``)."""
        return dict(self._consumed)

    @classmethod
    def restore(cls, snapshot):
        """Hydrate a store from a :meth:`snapshot` dict."""
        store = cls()
        if isinstance(snapshot, dict):
            for nonce, at in snapshot.items():
                _check_hex32(nonce, "nonce")
                store._consumed[nonce] = at
        return store

    def consume(self, nonce, now=None):
        """Consume a nonce. Raises approval-token-replayed on double
        consumption. Returns True on first consumption."""
        _check_hex32(nonce, "nonce")
        if nonce in self._consumed:
            _fail(REPLAYED,
                  "nonce %s... already consumed at %d; a token "
                  "authorizes at most one execution"
                  % (nonce[:12], self._consumed[nonce]))
        at = int(time.time()) if now is None else now
        self._consumed[nonce] = at
        return True


def _args_match(binding, args):
    """True when the presented args satisfy the token's binding."""
    if binding["mode"] == "exact":
        if not isinstance(args, dict):
            return False
        return _canonical(args) == _canonical(binding["args"])
    # schema mode: exactly the declared keys, each value in its enum
    # (type-strict via canonical form: 1 != "1" != True).
    if not isinstance(args, dict):
        return False
    schema = binding["schema"]
    if set(args.keys()) != set(schema.keys()):
        return False
    for key, constraint in schema.items():
        presented = _canonical(args[key])
        if not any(presented == _canonical(v)
                   for v in constraint["enum"]):
            return False
    return True


def verify_token(token, *, capability, args, now=None,
                 consume_store=None):
    """Verify a token against a presented (capability, args) action.

    Order: shape, seal (tamper), future-issue, expiry, capability,
    arguments, replay. Returns the verified token body on success;
    raises a coded :class:`ApprovalTokenError` otherwise. The nonce is
    NOT consumed here -- the caller consumes it via
    ``consume_store.consume(body["nonce"])`` on its durable-claim
    path (verify-then-consume keeps a refused-later record
    retriable).
    """
    _check_shape(token)
    if not _seal_ok(token):
        _fail(TAMPERED,
              "the seal does not recompute under the pinned key epoch; "
              "the token was edited after minting")
    at = int(time.time()) if now is None else now
    if not isinstance(at, int) or isinstance(at, bool):
        _fail(MALFORMED, "now must be an int epoch")
    if token["issued_at"] > at:
        _fail(MALFORMED, "token is not yet active (issued_at in the "
                         "future)")
    if at >= token["expires_at"]:
        _fail(EXPIRED,
              "token expired: issued_at=%d expires_at=%d now=%d"
              % (token["issued_at"], token["expires_at"], at))
    if not isinstance(capability, str) or capability != token["capability"]:
        _fail(CAPABILITY_MISMATCH,
              "token authorizes capability %r, not %r"
              % (token["capability"], capability))
    if not _args_match(token["argument_binding"], args):
        _fail(ARGUMENT_MISMATCH,
              "presented arguments do not satisfy the token's argument "
              "binding (mode %r)"
              % (token["argument_binding"]["mode"],))
    if consume_store is not None:
        if consume_store.is_consumed(token["nonce"]):
            _fail(REPLAYED,
                  "nonce %s... was already consumed; a token "
                  "authorizes at most one execution"
                  % (token["nonce"][:12],))
    return {k: token[k] for k in _REQUIRED_FIELDS if k != "mac"}
