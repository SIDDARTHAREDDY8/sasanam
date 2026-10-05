"""Wave-333 lane 3: context-bound capability tokens.

Prospectus ADAPT #1 (EmpowerID/Omada): an approval minted today can be
replayed in a different context tomorrow. The ``approval_tokens``
seam binds capability + arguments + issuer + key epoch, but NOT the
presenting agent, the mission, the mission's tool set, or the policy
version -- the wave-333 red battery (``evals/w333_captoken_red.py``)
proves all four cross-context replays succeed on the base tree.

This module closes that gap by composition, not by new crypto: it
wraps an ``approval_tokens`` inner token and binds the approval to

    SHA256(agent_id || mission_id || tool_set || policy_version)

computed over canonical JSON bytes joined with 0x00 separators. The
outer seal is HMAC-SHA256 under the active log HMAC key (the same F34
key ceremony as ``approval_tokens``) with its OWN domain separator
(``capability-token-v1:``), covering the inner token's MAC -- so the
inner token cannot be swapped under a valid outer seal.

Mint at approval time (``mint_context_token``); verify at use time
(``verify_context_token``). Verification is fail-closed and ordered
cheap-to-expensive: shape, seal, expiry, context (agent, mission,
tools, policy -- each with its own coded refusal), then the inner
token's own verification (capability/arguments/replay refusals
propagate unchanged). Every refusal is a coded
``CapabilityTokenError`` (``capability-token-*`` vocabulary,
registered in the decision-code taxonomy).

Honest boundary (threat model): like ``approval_tokens``, the seal
rides the log HMAC key, so this is an independent BINDING check, not
key-compromise resistance -- a key-holder could mint a conforming
token directly. Its value is against cross-context reuse: a token
legitimately minted for agent A / mission X cannot authorize agent B,
mission Y, a widened tool set, or a rotated policy, and the check is
independent of the inner token's seal so an inner-binding bug does not
collapse both.

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
    from . import approval_tokens as _AT
    from . import decision_codes as _dc
except ImportError:  # standalone: sibling modules beside this file
    from log import _active_key
    from egress_ledger import _ledger_keyring
    import approval_tokens as _AT
    import decision_codes as _dc

TOKEN_VERSION = 1
_MAC_DOMAIN = b"capability-token-v1:"
_CONTEXT_SEP = b"\x00"

MALFORMED = "capability-token-malformed"
TAMPERED = "capability-token-tampered"
EXPIRED = "capability-token-expired"
AGENT_MISMATCH = "capability-token-agent-mismatch"
MISSION_MISMATCH = "capability-token-mission-mismatch"
TOOLS_MISMATCH = "capability-token-tools-mismatch"
POLICY_STALE = "capability-token-policy-stale"

MAX_STR_LEN = 256
MAX_TOOLS = 64

_REQUIRED_FIELDS = ("v", "inner", "context", "context_digest",
                    "key_epoch", "mac")
_CONTEXT_FIELDS = ("agent_id", "mission_id", "tool_set", "policy_version")


class CapabilityTokenError(Exception):
    """Code-first exception: ``code`` is a taxonomy machine code."""

    def __init__(self, code, detail=""):
        _dc.code_for(code)  # fail closed: unmapped codes never leave
        super(CapabilityTokenError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _fail(code, detail):
    raise CapabilityTokenError(code, detail)


def _canonical(obj):
    """Canonical bytes for sealing/comparison. Only JSON-native values
    are sealable -- anything else is malformed, never silently
    coerced (a coercion could bind two different values to one seal)."""
    try:
        return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=True).encode("utf-8")
    except (TypeError, ValueError) as e:
        _fail(MALFORMED, "not canonicalizable: %s" % (e,))


def _check_str(value, what):
    if not isinstance(value, str) or not value:
        _fail(MALFORMED, "%s must be a non-empty string; got %r"
              % (what, value))
    if len(value) > MAX_STR_LEN:
        _fail(MALFORMED, "%s exceeds %d chars" % (what, MAX_STR_LEN))
    return value


def _check_hex64(value, what):
    if not isinstance(value, str) or len(value) != 64:
        _fail(MALFORMED, "%s must be 64 hex chars; got %r"
              % (what, value))
    try:
        raw = bytes.fromhex(value)
    except ValueError:
        _fail(MALFORMED, "%s is not hex: %r" % (what, value))
    if raw.hex() != value:
        _fail(MALFORMED, "%s must be lowercase hex; got %r"
              % (what, value))
    return value


def _normalize_tool_set(tool_set):
    """Normalize the bound tool set: sorted, de-duplicated, all
    non-empty strings. The binding is order-insensitive (a set), but
    the canonical form is fixed so the digest is stable."""
    if isinstance(tool_set, tuple):
        tool_set = list(tool_set)
    if not isinstance(tool_set, list) or not tool_set:
        _fail(MALFORMED, "tool_set must be a non-empty list of tool "
                         "names; got %r" % (tool_set,))
    if len(tool_set) > MAX_TOOLS:
        _fail(MALFORMED, "tool_set exceeds %d tools" % MAX_TOOLS)
    for t in tool_set:
        _check_str(t, "tool_set entry")
    return sorted(set(tool_set))


def _context_digest(agent_id, mission_id, tool_set, policy_version):
    """SHA256(agent_id || mission_id || tool_set || policy_version).

    Each input is canonicalized to JSON bytes first and joined with
    0x00 separators. JSON strings can never contain a raw 0x00 byte
    (ensure_ascii escapes it as \\u0000), so the join is unambiguous:
    no two distinct field tuples produce the same preimage.
    """
    parts = [_canonical(agent_id), _canonical(mission_id),
             _canonical(tool_set), _canonical(policy_version)]
    return hashlib.sha256(_CONTEXT_SEP.join(parts)).hexdigest()


def _seal(body, key, key_epoch):
    msg = (_MAC_DOMAIN + key_epoch.encode("utf-8") + b"|"
           + _canonical(body))
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def mint_context_token(agent_id, mission_id, tool_set, policy_version,
                       *, capability, argument_binding, issuer,
                       ttl_seconds, issued_at=None, nonce=None):
    """Mint a context-bound capability token at approval time.

    Binds the approval to (agent_id, mission_id, tool_set,
    policy_version) via the context digest, and to
    (capability, argument_binding) via the wrapped inner approval
    token. Never executes. Returns the token dict (JSON-native, frozen
    by the seal).

    The seal is HMAC-SHA256 under the active log HMAC key (the F34 key
    ceremony) with the key epoch bound in. Without a configured key
    ``_active_key()`` raises -- fail closed, no fallback.
    """
    _check_str(agent_id, "agent_id")
    _check_str(mission_id, "mission_id")
    tools = _normalize_tool_set(tool_set)
    _check_str(policy_version, "policy_version")
    if nonce is None:
        nonce = secrets.token_hex(16)
    inner = _AT.issue_token(capability, argument_binding, issuer=issuer,
                            ttl_seconds=ttl_seconds, issued_at=issued_at,
                            nonce=nonce)
    key, key_epoch = _active_key()
    context = {"agent_id": agent_id,
               "mission_id": mission_id,
               "tool_set": tools,
               "policy_version": policy_version}
    digest = _context_digest(agent_id, mission_id, tools, policy_version)
    body = {
        "v": TOKEN_VERSION,
        "inner": inner,
        "context": context,
        "context_digest": digest,
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
    context = token.get("context")
    if not isinstance(context, dict):
        _fail(MALFORMED, "context must be a dict; got %r"
              % (type(context),))
    if set(context.keys()) != set(_CONTEXT_FIELDS):
        _fail(MALFORMED, "context has unknown/missing fields: %r"
              % sorted(set(context.keys()) ^ set(_CONTEXT_FIELDS)))
    _check_str(context["agent_id"], "context.agent_id")
    _check_str(context["mission_id"], "context.mission_id")
    # Validated but NOT normalized in place: the seal was computed over
    # the exact stored bytes (mint always stores normalized form), so
    # _seal_ok must run over the token as presented. Normalization for
    # comparison happens in verify_context_token.
    _normalize_tool_set(context["tool_set"])
    _check_str(context["policy_version"], "context.policy_version")
    _check_hex64(token.get("context_digest"), "context_digest")
    _check_str(token["key_epoch"], "key_epoch")
    _check_hex64(token.get("mac"), "mac")
    inner = token.get("inner")
    if not isinstance(inner, dict):
        _fail(MALFORMED, "inner token must be a dict; got %r"
              % (type(inner),))
    # The inner token's full shape is re-validated by
    # approval_tokens.verify_token at step 5; here we need only the
    # expiry field for the cheap-to-expensive order (shape, seal,
    # expiry before context).
    expires_at = inner.get("expires_at")
    if not isinstance(expires_at, int) or isinstance(expires_at, bool) \
            or expires_at < 0:
        _fail(MALFORMED, "inner.expires_at must be a non-negative int "
                         "epoch")
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


def verify_context_token(token, *, agent_id, mission_id, tool_set,
                         policy_version, capability, args, now=None,
                         consume_store=None):
    """Verify a context-bound token against the presented context.

    Order: shape, seal (tamper), expiry, context (agent, mission,
    tools, policy -- each a distinct coded refusal), then the inner
    approval token's own verification (its capability/argument/replay
    refusals propagate unchanged). Returns the verified bound context
    dict on success; raises a coded :class:`CapabilityTokenError`
    otherwise.

    ``consume_store`` (optional) is passed through to the inner
    ``approval_tokens.verify_token`` -- a consumed nonce there refuses
    ``approval-token-replayed``.
    """
    _check_shape(token)
    if not _seal_ok(token):
        _fail(TAMPERED,
              "the seal does not recompute under the pinned key epoch; "
              "the token was edited after minting")
    at = int(time.time()) if now is None else now
    if not isinstance(at, int) or isinstance(at, bool):
        _fail(MALFORMED, "now must be an int epoch")
    if at >= token["inner"]["expires_at"]:
        _fail(EXPIRED,
              "token expired: expires_at=%d now=%d"
              % (token["inner"]["expires_at"], at))
    bound = token["context"]
    bound_tools = _normalize_tool_set(bound["tool_set"])
    if not isinstance(agent_id, str) or agent_id != bound["agent_id"]:
        _fail(AGENT_MISMATCH,
              "token is bound to agent %r, not %r"
              % (bound["agent_id"], agent_id))
    if not isinstance(mission_id, str) or mission_id != bound["mission_id"]:
        _fail(MISSION_MISMATCH,
              "token is bound to mission %r, not %r"
              % (bound["mission_id"], mission_id))
    presented_tools = _normalize_tool_set(tool_set)
    if presented_tools != bound_tools:
        _fail(TOOLS_MISMATCH,
              "token is bound to tool set %r, not %r"
              % (bound_tools, presented_tools))
    if not isinstance(policy_version, str) \
            or policy_version != bound["policy_version"]:
        _fail(POLICY_STALE,
              "token is bound to policy version %r, not %r; re-approval "
              "under the current policy mints a fresh token"
              % (bound["policy_version"], policy_version))
    # Defense in depth: the digest recomputes from the presented
    # (already field-matched) context. A mismatch here means the
    # stored digest was edited under a valid seal -- impossible
    # without the key, but fail closed anyway.
    if _context_digest(agent_id, mission_id, presented_tools,
                       policy_version) != token["context_digest"]:
        _fail(TAMPERED,
              "context digest does not recompute from the presented "
              "context")
    _AT.verify_token(token["inner"], capability=capability, args=args,
                     now=at, consume_store=consume_store)
    return {"agent_id": bound["agent_id"],
            "mission_id": bound["mission_id"],
            "tool_set": list(bound_tools),
            "policy_version": bound["policy_version"]}
