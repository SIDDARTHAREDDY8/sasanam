"""MCP token scope enforcement at every tool call (W244-2 ADAPT).

Adapts the THREAT MODEL of the GitLab 2026-09-23 critical patch
(CVE-2026-92874: MCP-scoped token scope unenforced, 5.4) and the
Artifactory CVE-2026-42016 scope-widening class as PROSE ONLY: no
advisory text is read, copied, imported, or vendored here. The
mechanism: a token minted with a scope carries that scope as a
deployment-signed grant checked on EACH invocation, not just at
mint time.

Layers (verification order is fixed):

1. The transactional token is verified first via
   ``gov.transactional_tokens.TransactionalTokenIssuer.verify``
   (shape -> MAC -> expiry -> audience -> txn binding; its
   ``transaction-*`` refusals are reused, never duplicated). A
   scope check never runs on an unverified token.
2. The sealed scope POLICY is re-authenticated (HMAC over canonical
   bytes): an agent that rewrites its own scope policy fails with
   ``scope-policy-tampered``. Undeclared tools/actions fail closed
   with ``tool-scope-undeclared`` -- authority never auto-expands.
3. The scope GRANT is authenticated and bound to the exact token it
   was issued for (``token_digest`` = sha256 of the token's MAC): a
   grant presented with a refreshed token refuses
   ``scope-grant-unbound`` (probe c: scope narrowing mid-session
   requires a NEW grant; the old grant does not follow the token).
4. Coverage is checked against the PRESENTED tool name, not the
   policy's alias target: a grant for ``file_read`` does not cover
   a call arriving as the alias ``quick_read`` unless the
   deployment granted the alias explicitly (anti-widening,
   ``token-scope-exceeded``).

The choke point: ``run_scoped_call(verdict, tool_name, action,
call_fn)`` executes ``call_fn`` only when the verdict was granted
for exactly (tool_name, action); a replayed verdict refuses
``scope-verdict-mismatched``. The executor never sees the token or
the grant -- only the verdict -- so the check cannot be skipped.

Composition: ``authorize_tool_call`` runs the
``gov.mcp_surface_guard`` quarantine first (its
``tool-executable-content`` / ``tool-definition-malformed``
refusals surface unchanged), then ``check_scope``.

Refusal vocabulary (domain ``token-scope``, all fail-closed):

* ``token-scope-exceeded`` -- the grant does not cover (tool, action)
  (also covers alias-not-granted anti-widening).
* ``token-scope-unparseable`` -- a presented runtime input (grant,
  policy wrapper, tool name, action, epoch) is malformed.
* ``tool-scope-undeclared`` -- tool or action absent from the sealed
  policy; fail closed, never auto-expand.
* ``scope-policy-tampered`` -- the sealed policy's MAC does not
  cover its spec bytes, or the spec is malformed.
* ``scope-grant-tampered`` -- the grant's MAC does not cover its
  body (tamper is reported as tamper, never as a scope gap).
* ``scope-grant-unbound`` -- the grant is bound to a different
  token than the one presented.
* ``scope-verdict-mismatched`` -- a verdict presented for different
  (tool, action) parameters than it was granted for.
* ``scope-key-missing`` -- no deployment key supplied; fails closed
  (no dev-key fallback, same discipline as transactional tokens).

Honest boundaries:
- A grant's lifetime rides the transactional token's very-short
  lifetime (the token is verified first; an expired token refuses
  ``transaction-expired`` before any scope logic runs). There is no
  separate grant expiry.
- The grant's ``sub`` (subject) is carried as audit data; subject
  enforcement belongs to ``gov.mcp_invocation_authz``'s
  trust-anchored subject, not to this layer.
- Required-scope coverage is a set comparison over deployment-chosen
  scope strings; this layer does not define what "files:read" means.
- Grant MACs prove shared-secret authenticity (HMAC), not
  non-repudiation; key custody and token transport protection are
  deployment-owned.

Stdlib only. Deterministic: injectable clock, no I/O, no network.
"""

import hashlib
import hmac
import json
from typing import Any, Dict, Mapping, NamedTuple, Optional, Tuple

TOKEN_SCOPE_EXCEEDED = "token-scope-exceeded"
TOKEN_SCOPE_UNPARSEABLE = "token-scope-unparseable"
TOOL_SCOPE_UNDECLARED = "tool-scope-undeclared"
SCOPE_POLICY_TAMPERED = "scope-policy-tampered"
SCOPE_GRANT_TAMPERED = "scope-grant-tampered"
SCOPE_GRANT_UNBOUND = "scope-grant-unbound"
SCOPE_VERDICT_MISMATCHED = "scope-verdict-mismatched"
SCOPE_KEY_MISSING = "scope-key-missing"

CODES = (
    TOKEN_SCOPE_EXCEEDED,
    TOKEN_SCOPE_UNPARSEABLE,
    TOOL_SCOPE_UNDECLARED,
    SCOPE_POLICY_TAMPERED,
    SCOPE_GRANT_TAMPERED,
    SCOPE_GRANT_UNBOUND,
    SCOPE_VERDICT_MISMATCHED,
    SCOPE_KEY_MISSING,
)

_GRANT_DOMAIN = b"gov-scope-grant/v1\x00"
_POLICY_DOMAIN = b"gov-scope-policy/v1\x00"
_GRANT_VERSION = 1


class TokenScopeError(Exception):
    """Fail-closed scope refusal. ``code`` is the machine code."""

    def __init__(self, code, detail=""):
        super(TokenScopeError, self).__init__(
            "%s%s" % (code, (": %s" % detail) if detail else ""))
        self.code = code
        self.detail = detail


def _refuse(code, detail=""):
    raise TokenScopeError(code, detail)


def _canonical_bytes(obj):
    """RFC-8785-shaped canonical bytes (sorted keys, minimal separators)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _mac(key, domain, body):
    return hmac.new(key, domain + _canonical_bytes(body),
                    hashlib.sha256).hexdigest()


def _require_epoch(value, name):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _refuse(TOKEN_SCOPE_UNPARSEABLE,
                "%s %r is not a numeric epoch" % (name, value))
    return value


def _require_nonempty_str(value, name):
    if not isinstance(value, str) or not value:
        _refuse(TOKEN_SCOPE_UNPARSEABLE,
                "%s must be a non-empty string" % (name,))
    return value


def _key_or_refuse(key):
    if not isinstance(key, bytes) or not key:
        _refuse(SCOPE_KEY_MISSING,
                "no deployment key supplied; failing closed "
                "(no dev-key fallback)")
    return key


def _token_digest(tok):
    """Bind a grant to the exact token: sha256 of the token's MAC.

    Callers must use this only AFTER the token's MAC has been
    authenticated (``TransactionalTokenIssuer.verify`` strips ``mac``
    from its return value, so the digest is taken from the presented
    token dict post-verification).
    """
    return hashlib.sha256(tok["mac"].encode("utf-8")).hexdigest()


class ScopeVerdict(NamedTuple):
    """Granted scope check for one (tool, action) call.

    ``token_digest`` binds the verdict to the exact token presented
    at check time; ``policy_digest`` binds it to the exact sealed
    policy bytes. The executor re-validates the (tool, action) pair
    in :func:`run_scoped_call`.
    """
    tool: str
    action: str
    token_digest: str
    policy_digest: str
    granted_scopes: Tuple[str, ...]


class ScopeGrantIssuer(object):
    """Issue and verify deployment-signed scope grants.

    ``key`` must be non-empty bytes; ``None`` (or anything else)
    builds an issuer whose every operation refuses
    ``scope-key-missing`` -- no silent fallback.
    """

    def __init__(self, key):
        self._key = key if isinstance(key, bytes) and key else None

    def _key_or_refuse(self):
        return _key_or_refuse(self._key)

    def issue_grant(self, subject, token_digest, scope_map, now):
        """Mint a scope grant bound to one token.

        ``scope_map``: {tool_name: [scope strings]}. ``token_digest``
        is the sha256-of-MAC from :func:`_token_digest` of the exact
        token this grant travels with. ``now`` is required and
        injectable (no clock read).
        """
        key = self._key_or_refuse()
        _require_nonempty_str(subject, "subject")
        _require_nonempty_str(token_digest, "token_digest")
        if not isinstance(scope_map, dict) or not scope_map:
            _refuse(TOKEN_SCOPE_UNPARSEABLE,
                    "scope_map must be a non-empty dict")
        scopes = {}
        for tool, granted in scope_map.items():
            _require_nonempty_str(tool, "scope tool")
            if not isinstance(granted, (list, tuple)) or not granted:
                _refuse(TOKEN_SCOPE_UNPARSEABLE,
                        "scopes for tool %r must be a non-empty list"
                        % (tool,))
            seen = []
            for scope in granted:
                _require_nonempty_str(scope, "scope")
                if scope not in seen:
                    seen.append(scope)
            scopes[tool] = seen
        now = _require_epoch(now, "now")
        body = {"v": _GRANT_VERSION, "sub": subject,
                "token_digest": token_digest, "scopes": scopes,
                "iat": now}
        body["mac"] = _mac(key, _GRANT_DOMAIN, body)
        return body


def _require_grant_shape(grant):
    if not isinstance(grant, dict):
        _refuse(TOKEN_SCOPE_UNPARSEABLE, "grant must be a dict")
    for field in ("v", "sub", "token_digest", "scopes", "iat", "mac"):
        if field not in grant:
            _refuse(TOKEN_SCOPE_UNPARSEABLE,
                    "grant missing field %r" % (field,))
    if grant["v"] != _GRANT_VERSION:
        _refuse(TOKEN_SCOPE_UNPARSEABLE,
                "unsupported grant version %r" % (grant["v"],))
    _require_nonempty_str(grant["sub"], "grant sub")
    _require_nonempty_str(grant["token_digest"], "grant token_digest")
    _require_epoch(grant["iat"], "grant iat")
    if not isinstance(grant["scopes"], dict):
        _refuse(TOKEN_SCOPE_UNPARSEABLE, "grant scopes must be a dict")
    if not isinstance(grant["mac"], str) or not grant["mac"]:
        _refuse(TOKEN_SCOPE_UNPARSEABLE,
                "grant mac must be a non-empty string")


def _verify_grant_mac(grant, key):
    body = {"v": grant["v"], "sub": grant["sub"],
            "token_digest": grant["token_digest"],
            "scopes": grant["scopes"], "iat": grant["iat"]}
    if not hmac.compare_digest(_mac(key, _GRANT_DOMAIN, body),
                               grant["mac"]):
        _refuse(SCOPE_GRANT_TAMPERED,
                "grant MAC does not cover the presented bytes")


def seal_policy(scope_key, spec):
    """Seal a scope policy spec under the deployment key.

    ``spec``: {"tools": {tool: {action: [required scopes]}},
               "aliases": {alias: canonical tool}} ("aliases" optional).
    Returns {"spec": spec, "mac": hex}. The MAC is re-verified at
    EVERY check_scope call: a rewritten policy fails closed.
    """
    key = _key_or_refuse(scope_key)
    if not isinstance(spec, dict):
        _refuse(SCOPE_POLICY_TAMPERED, "policy spec must be a dict")
    tools = spec.get("tools")
    if not isinstance(tools, dict) or not tools:
        _refuse(SCOPE_POLICY_TAMPERED,
                "policy spec needs a non-empty 'tools' mapping")
    aliases = spec.get("aliases", {})
    if not isinstance(aliases, dict):
        _refuse(SCOPE_POLICY_TAMPERED, "policy 'aliases' must be a dict")
    unknown = sorted(k for k in spec.keys() if k not in ("tools", "aliases"))
    if unknown:
        _refuse(SCOPE_POLICY_TAMPERED,
                "unknown policy keys: %s" % (", ".join(unknown),))
    for tool, actions in tools.items():
        _require_nonempty_str(tool, "policy tool")
        if not isinstance(actions, dict) or not actions:
            _refuse(SCOPE_POLICY_TAMPERED,
                    "tool %r needs a non-empty action mapping" % (tool,))
        for action, required in actions.items():
            _require_nonempty_str(action, "policy action")
            if not isinstance(required, (list, tuple)) or not required:
                _refuse(SCOPE_POLICY_TAMPERED,
                        "action %r of tool %r needs a non-empty scope list"
                        % (action, tool))
            for scope in required:
                _require_nonempty_str(scope, "required scope")
    for alias, canonical in aliases.items():
        _require_nonempty_str(alias, "alias")
        _require_nonempty_str(canonical, "alias target")
        if canonical not in tools:
            _refuse(SCOPE_POLICY_TAMPERED,
                    "alias %r targets undeclared tool %r"
                    % (alias, canonical))
    return {"spec": spec, "mac": _mac(key, _POLICY_DOMAIN, spec)}


def _unseal_policy(sealed_policy, scope_key):
    """Re-authenticate the sealed policy; return (spec, policy_digest)."""
    key = _key_or_refuse(scope_key)
    if not isinstance(sealed_policy, dict):
        _refuse(SCOPE_POLICY_TAMPERED, "sealed policy must be a dict")
    spec = sealed_policy.get("spec")
    mac = sealed_policy.get("mac")
    if not isinstance(spec, dict) or not isinstance(mac, str) or not mac:
        _refuse(SCOPE_POLICY_TAMPERED,
                "sealed policy must carry a spec dict and a MAC")
    if not hmac.compare_digest(_mac(key, _POLICY_DOMAIN, spec), mac):
        _refuse(SCOPE_POLICY_TAMPERED,
                "policy MAC does not cover the presented spec bytes")
    # Shape re-check: a spec that cannot be a policy is untrusted.
    try:
        seal_policy(key, spec)
    except TokenScopeError:
        _refuse(SCOPE_POLICY_TAMPERED,
                "policy spec fails shape validation")
    policy_digest = hashlib.sha256(_canonical_bytes(spec)).hexdigest()
    return spec, policy_digest


def check_scope(sealed_policy, tok, grant, tool_name, action, now,
                txn_key, scope_key, expected_txn_id,
                expected_rs_audience):
    """Check one (tool, action) call against the sealed policy and grant.

    Check order (fixed): input shape -> transactional-token verify
    (reuses ``transaction-*`` refusals) -> policy re-authentication ->
    tool/action declaration -> grant shape -> grant MAC -> grant
    token binding -> scope coverage. Returns a :class:`ScopeVerdict`
    on success; raises :class:`TokenScopeError` otherwise.
    """
    _require_nonempty_str(tool_name, "tool_name")
    _require_nonempty_str(action, "action")
    now = _require_epoch(now, "now")

    from . import transactional_tokens as _tt
    # Raises the transaction-* refusals; also authenticates tok["mac"].
    _tt.TransactionalTokenIssuer(txn_key).verify(
        tok, expected_txn_id, expected_rs_audience, now)

    spec, policy_digest = _unseal_policy(sealed_policy, scope_key)

    canonical_tool = spec.get("aliases", {}).get(tool_name, tool_name)
    actions = spec["tools"].get(canonical_tool)
    if actions is None:
        _refuse(TOOL_SCOPE_UNDECLARED,
                "tool %r is not declared in the sealed policy" % (tool_name,))
    required = actions.get(action)
    if required is None:
        _refuse(TOOL_SCOPE_UNDECLARED,
                "action %r of tool %r is not declared" % (action, tool_name))

    _require_grant_shape(grant)
    _verify_grant_mac(grant, _key_or_refuse(scope_key))

    # The grant travels with exactly one token. The digest is taken
    # from the PRESENTED token dict: verify() already authenticated
    # its MAC above, and returns a mac-less body.
    digest = _token_digest(tok)
    if grant["token_digest"] != digest:
        _refuse(SCOPE_GRANT_UNBOUND,
                "grant is bound to a different token than presented")

    # Anti-widening: coverage is checked against the PRESENTED name,
    # never the alias target.
    granted = grant["scopes"].get(tool_name)
    if granted is None or not set(required) <= set(granted):
        _refuse(TOKEN_SCOPE_EXCEEDED,
                "grant covers %r for %r; %r requires %r"
                % (granted, tool_name, action, list(required)))
    return ScopeVerdict(tool=tool_name, action=action,
                        token_digest=digest, policy_digest=policy_digest,
                        granted_scopes=tuple(granted))


def run_scoped_call(verdict, tool_name, action, call_fn):
    """Execute ``call_fn`` only on an exact verdict match.

    The choke point: the executor signature requires the verdict
    object. A verdict granted for other parameters refuses
    ``scope-verdict-mismatched`` and the call never runs.
    """
    if not isinstance(verdict, ScopeVerdict):
        _refuse(SCOPE_VERDICT_MISMATCHED,
                "no scope verdict presented to the executor")
    if verdict.tool != tool_name or verdict.action != action:
        _refuse(SCOPE_VERDICT_MISMATCHED,
                "verdict granted for (%r, %r), presented for (%r, %r)"
                % (verdict.tool, verdict.action, tool_name, action))
    return call_fn()


def authorize_tool_call(sealed_policy, tool_def, tok, grant, action, now,
                        txn_key, scope_key, expected_txn_id,
                        expected_rs_audience, endpoint_public=True):
    """Full call-time authorization: quarantine first, then scope.

    Runs ``gov.mcp_surface_guard.quarantine_tool_definition`` on the
    tool definition BEFORE any scope logic: a quarantined definition
    refuses with the surface guard's own codes (never duplicated
    here). Returns the :class:`ScopeVerdict` for the executor.
    """
    from . import mcp_surface_guard as _msg
    _msg.quarantine_tool_definition(tool_def,
                                   endpoint_public=endpoint_public)
    tool_name = tool_def.get("name")
    return check_scope(sealed_policy, tok, grant, tool_name, action, now,
                       txn_key, scope_key, expected_txn_id,
                       expected_rs_audience)
