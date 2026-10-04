#!/usr/bin/env python3
"""Least-privilege grant negotiation surface (wave-319 lane 1).

Agent->tool authorization in Sasanam is all-or-nothing (role allowlists,
capability gates, the provenance sink). There is no vocabulary for a NARROW
grant -- "this agent may call send_email with action=send on
resource=mallory@evil.com, and nothing else" -- and three failure classes are
invisible: the RFC 9396 S2.2 product-of-fields over-grant trap (one object
naming actions=[read,write] x resources=[contacts,photos] authorizes 4
permissions, not 2), widening on delegation, and stale grants.

This module builds the prospectus composition
(research/prospecting/w318_agent_identity_discovery.md, S2 + direction brief
S5c) in Sasanam's native policy engine, stdlib-only, no new wire format:

* a grant grammar shaped like RAR (RFC 9396) ``authorization_details`` --
  typed objects with ``type``, ``tool``, ``actions``, ``resources``,
  ``constraints``, ``identifier``, ``privileges`` -- plus ``issued_at`` /
  ``expires_at``, ``issuer``, ``audience``, ``parent`` (delegation link) and
  an Ed25519 ``signature``;
* structural validators, including the MANDATORY product-of-fields check:
  one object per (tool, resource) pair, fail closed on multiplicative
  privilege;
* attenuation: derived grants may only narrow (the wave-178 in-toto /
  only-tighten principle);
* expiry-as-revocation: short-TTL grants (at most one hour); no revocation
  list in v1;
* chain-of-proofs verification for delegated grants (UCAN discipline): every
  hop signed, each hop equal-or-narrower, chain root anchored at the tool's
  registered resource owner, audience binding on the presenting agent;
* verifier-side policy (the tool's registered grant policy) AND token-side
  checks (the grant's internal consistency) must both pass (Biscuit
  semantics);
* a deployment-owned ``GrantRegistry`` where risky tools are registered
  with the grant types they accept (AS-metadata-style advertisement for
  tool discovery);
* ``advisory_check``: the only-tighten advisory entry point for the
  tool-call path. Absent registry, unregistered tool, or absent grant ->
  the existing policy path proceeds unchanged. A presented grant is fully
  verified; any failure refuses with a coded refusal. The layer can only
  turn allow into deny, never deny into allow.

Decision codes (the ``grantneg-`` namespace is deliberate: the tree already
has ``grant-*`` codes owned by ``gov/grant_attenuation.py``'s digest-chain
delegation, capability assessment, and authorization receipts; one code
string is one taxonomy record, so reusing a string would misattribute
evidence):

* ``grantneg-malformed`` -- the grant/request fails the grammar or shape
  check (fail-closed construction/verification);
* ``grantneg-product-of-fields`` -- one grant object names more than one
  (tool, resource) pair (RFC 9396 S2.2 trap);
* ``grantneg-widening-refused`` -- ``derive()`` asked for a delegation that
  is not strictly narrower (fail-fast at construction);
* ``grantneg-expired`` -- the grant's TTL lapsed (expiry-as-revocation);
* ``grantneg-chain-unverifiable`` -- a chain link's signature does not
  verify, its issuer key is unknown, or parent linkage is broken;
* ``grantneg-chain-widened`` -- a delegation hop is not equal-or-narrower;
* ``grantneg-anchor-untrusted`` -- the chain root's issuer is not the
  tool's registered resource owner;
* ``grantneg-audience-mismatch`` -- the final link's audience does not
  match the presenting agent.

* ``grantneg-scope-mismatch`` -- the grant does not cover this call:
  the grant's tool differs from the called tool, or the grant's
  resource differs from the call's resource locator.

Relationship to ``gov/grant_attenuation.py``: that module is digest-chain
delegation without signatures, expiry, or a request grammar; this module is
signature-based (Ed25519) with expiry and a negotiation surface. The two do
not interoperate; each keeps its own code namespace.

Stdlib only. No network. $0.

HONEST RESIDUALS (never claimed away):

* The TTL bound (1 hour) and clock trust are deployment-owned (same as
  ``gov/attenuation.py``); ``now`` is injectable for determinism.
* The chain root's owner-key registration is a deployment ceremony --
  "who guards the minter?" is the same deployment question as the
  agent-identity registry.
* Delegation is bearer-capability style (Biscuit model): anyone holding the
  parent grant bytes can mint a narrowed child. ATTENUATION, not issuer
  identity, is the security property -- a stranger cannot widen, only
  narrow. The child's signature binds its content to the delegator's key
  for audit, not for authorization.
* Resource locators are opaque strings; sub-resource (prefix) narrowing is
  not modeled in v1 -- a derived grant's resource must equal the parent's.
* ``verify_chain`` allows exact-copy hops (equal-or-narrower, UCAN
  discipline); ``derive()`` requires STRICT narrowing (a rights copy is a
  caller error at construction). Verification is about safety (no
  escalation); construction is about intent (delegation means narrowing).
"""

import hashlib
import json
from datetime import datetime, timedelta, timezone

from .ed25519 import sign as _ed_sign
from .ed25519 import verify as _ed_verify

# ---------------------------------------------------------------------------
# Error vocabulary.
# ---------------------------------------------------------------------------


class GrantError(Exception):
    """Base class for all grant refusals. ``code`` is machine-readable and
    maps 1:1 to the decision-code taxonomy."""

    code = "grantneg-malformed"

    def __init__(self, message="", code=None):
        super().__init__(message)
        if code is not None:
            self.code = code


class GrantMalformedError(GrantError):
    """The grant or request fails the grammar/shape check."""

    code = "grantneg-malformed"


class GrantProductOfFieldsError(GrantError):
    """One grant object names more than one (tool, resource) pair --
    the RFC 9396 S2.2 multiplicative-privilege trap."""

    code = "grantneg-product-of-fields"


class GrantWideningRefusedError(GrantError):
    """derive() was asked for a delegation that is not strictly
    narrower than its parent."""

    code = "grantneg-widening-refused"


class GrantExpiredError(GrantError):
    """The grant's TTL lapsed (expiry-as-revocation)."""

    code = "grantneg-expired"


class GrantChainUnverifiableError(GrantError):
    """A chain link's signature does not verify, its issuer key is
    unknown, or parent linkage is broken."""

    code = "grantneg-chain-unverifiable"


class GrantChainWidenedError(GrantError):
    """A delegation hop is not equal-or-narrower than its parent."""

    code = "grantneg-chain-widened"


class GrantAnchorUntrustedError(GrantError):
    """The chain root's issuer is not the tool's registered resource
    owner."""

    code = "grantneg-anchor-untrusted"


class GrantAudienceMismatchError(GrantError):
    """The final link's audience does not match the presenting agent."""

    code = "grantneg-audience-mismatch"


class GrantScopeMismatchError(GrantError):
    """The grant does not cover this call: the grant's tool differs
    from the called tool, or the grant's resource differs from the
    call's resource locator."""

    code = "grantneg-scope-mismatch"


# ---------------------------------------------------------------------------
# Canonical encoding and digests.
# ---------------------------------------------------------------------------

GRANT_TYPE = "sasanam_tool_grant"

#: Maximum grant lifetime in seconds (short-TTL, K8s-token style).
MAX_TTL_SECONDS = 3600

_REQUIRED_FIELDS = (
    "type", "tool", "actions", "resources", "constraints", "identifier",
    "privileges", "issued_at", "expires_at", "issuer", "audience",
    "parent", "signature",
)


def canonical_bytes(obj):
    """Deterministic canonical encoding (sorted keys, compact separators,
    ASCII)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def grant_digest(grant):
    """SHA-256 hex digest of a grant's canonical form, excluding the
    signature (so ``parent`` links bind content, not the seal)."""
    body = {k: v for k, v in grant.items() if k != "signature"}
    return hashlib.sha256(canonical_bytes(body)).hexdigest()


def _parse_time(value, field):
    if not isinstance(value, str):
        raise GrantMalformedError(
            "%s must be an ISO-8601 string, got %r" % (field, type(value)))
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        raise GrantMalformedError(
            "%s is not parseable ISO-8601: %r" % (field, value))
    if dt.tzinfo is None:
        raise GrantMalformedError(
            "%s must be timezone-aware, got naive %r" % (field, value))
    return dt


def _as_pubkey_bytes(pubkey):
    if isinstance(pubkey, (bytes, bytearray)):
        return bytes(pubkey)
    if isinstance(pubkey, str):
        try:
            return bytes.fromhex(pubkey)
        except ValueError:
            raise GrantMalformedError(
                "pubkey hex is not parseable: %r" % (pubkey[:32],))
    raise GrantMalformedError(
        "pubkey must be bytes or hex str, got %r" % type(pubkey).__name__)


# ---------------------------------------------------------------------------
# Request grammar (RAR-shaped authorization_details).
# ---------------------------------------------------------------------------


def validate_request(objects):
    """Validate a grant REQUEST: a list of authorization-details objects.

    Each object must name exactly one tool (scalar) and exactly one
    resource (scalar, or a length-1 list). A multi-valued combination --
    the RFC 9396 S2.2 product -- refuses ``grantneg-product-of-fields``.
    Returns the list unchanged on success.
    """
    if not isinstance(objects, list) or not objects:
        raise GrantMalformedError(
            "grant request must be a non-empty list of objects")
    for obj in objects:
        if not isinstance(obj, dict):
            raise GrantMalformedError(
                "grant request object must be a dict, got %r"
                % type(obj).__name__)
        actions = obj.get("actions")
        if not isinstance(actions, list) or not actions or not all(
                isinstance(a, str) and a for a in actions):
            raise GrantMalformedError(
                "grant request object needs a non-empty actions list")
        tool = obj.get("tool")
        if not isinstance(tool, str) or not tool:
            # A list-valued tool multiplies with resources the same way.
            raise GrantProductOfFieldsError(
                "grant request object must name exactly one tool "
                "(scalar); multi-tool objects are multiplicative")
        resources = obj.get("resources")
        if isinstance(resources, str):
            continue
        if isinstance(resources, list) and len(resources) == 1 \
                and isinstance(resources[0], str):
            continue
        raise GrantProductOfFieldsError(
            "grant request object must name exactly one resource "
            "(scalar or length-1 list); got %r -- split into one "
            "object per (tool, resource) pair" % (resources,))
    return objects


def validate_grant(grant):
    """Validate a grant's GRAMMAR (shape + product-of-fields) without
    cryptographic verification or expiry checks.

    The counterpart to ``validate_request`` for issued grants: used
    where the shape must be checked but no key material is available
    (e.g., rendering a grant request in the approval queue). Returns
    the grant on success; raises the coded ``GrantError`` otherwise.
    For full verification (signature + expiry), use ``verify``.
    """
    _check_shape(grant)
    return grant


# ---------------------------------------------------------------------------
# Grant shape validation.
# ---------------------------------------------------------------------------


def _check_shape(grant):
    if not isinstance(grant, dict):
        raise GrantMalformedError(
            "grant must be a dict, got %r" % type(grant).__name__)
    missing = [f for f in _REQUIRED_FIELDS if f not in grant]
    if missing:
        raise GrantMalformedError(
            "grant is missing required fields: %s" % ", ".join(missing))
    if grant["type"] != GRANT_TYPE:
        raise GrantMalformedError(
            "unknown grant type %r (this surface issues %r)"
            % (grant["type"], GRANT_TYPE))
    if not isinstance(grant["tool"], str) or not grant["tool"]:
        raise GrantMalformedError("grant tool must be a non-empty string")
    actions = grant["actions"]
    if not isinstance(actions, list) or not actions or not all(
            isinstance(a, str) and a for a in actions):
        raise GrantMalformedError(
            "grant actions must be a non-empty list of strings")
    if not isinstance(grant["constraints"], dict):
        raise GrantMalformedError("grant constraints must be a dict")
    if not isinstance(grant["identifier"], str) or not grant["identifier"]:
        raise GrantMalformedError("grant identifier must be a non-empty string")
    if not isinstance(grant["privileges"], list):
        raise GrantMalformedError("grant privileges must be a list")
    if not isinstance(grant["issuer"], str) or not grant["issuer"]:
        raise GrantMalformedError("grant issuer must be a non-empty key id")
    if not isinstance(grant["audience"], str) or not grant["audience"]:
        raise GrantMalformedError("grant audience must be a non-empty agent id")
    parent = grant["parent"]
    if parent is not None and not (
            isinstance(parent, str) and len(parent) == 64
            and all(c in "0123456789abcdef" for c in parent)):
        raise GrantMalformedError(
            "grant parent must be None or a 64-hex digest")
    sig = grant["signature"]
    if not isinstance(sig, str):
        raise GrantMalformedError("grant signature must be a hex string")
    try:
        sig_bytes = bytes.fromhex(sig)
    except ValueError:
        raise GrantMalformedError("grant signature is not hex")
    if len(sig_bytes) != 64:
        raise GrantMalformedError("grant signature must be 64 bytes")
    # The product-of-fields check: exactly one (tool, resource) pair.
    # The scalar and length-1-list forms are equivalent (the latter
    # aids interop with array-style clients); both name one resource.
    resources = grant["resources"]
    if isinstance(resources, str):
        pass
    elif isinstance(resources, list) and len(resources) == 1 \
            and isinstance(resources[0], str):
        pass
    else:
        raise GrantProductOfFieldsError(
            "grant must name exactly one resource (scalar or length-1 "
            "list); got %r -- split into one grant per (tool, resource) "
            "pair" % (resources,))


def _check_times(grant, now):
    issued = _parse_time(grant["issued_at"], "issued_at")
    expires = _parse_time(grant["expires_at"], "expires_at")
    if issued > now:
        raise GrantMalformedError(
            "grant issued_at is in the future (clock-skew guard)")
    ttl = (expires - issued).total_seconds()
    if not 0 < ttl <= MAX_TTL_SECONDS:
        raise GrantMalformedError(
            "grant TTL must be in (0, %d] seconds, got %r"
            % (MAX_TTL_SECONDS, ttl))
    if expires <= now:
        raise GrantExpiredError(
            "grant %r expired at %s (expiry-as-revocation)"
            % (grant["identifier"], grant["expires_at"]))


def _check_signature(grant, pubkeys):
    issuer = grant["issuer"]
    if issuer not in pubkeys:
        raise GrantChainUnverifiableError(
            "grant issuer key id %r is unknown" % (issuer,))
    pub = _as_pubkey_bytes(pubkeys[issuer])
    body = {k: v for k, v in grant.items() if k != "signature"}
    msg = canonical_bytes(body)
    sig = bytes.fromhex(grant["signature"])
    # gov.ed25519.verify returns exact True/False, never raises
    # (wave-243 lesson: check the return, never truthiness).
    if _ed_verify(pub, msg, sig) is not True:
        raise GrantChainUnverifiableError(
            "grant %r signature does not verify under issuer %r"
            % (grant["identifier"], issuer))


# ---------------------------------------------------------------------------
# Attenuation (only-tighten).
# ---------------------------------------------------------------------------


def _single_resource(grant):
    r = grant["resources"]
    return r if isinstance(r, str) else r[0]


def _constraint_narrows(child_v, parent_v):
    """A child constraint value must not loosen the parent's."""
    if isinstance(parent_v, (int, float)) and isinstance(child_v, (int, float)) \
            and not isinstance(parent_v, bool) and not isinstance(child_v, bool):
        return child_v <= parent_v
    if isinstance(parent_v, list) and isinstance(child_v, list):
        return set(child_v) <= set(parent_v)
    return child_v == parent_v


def narrows(child, parent):
    """Pure predicate: is ``child`` equal-or-narrower than ``parent``?

    Rules: same tool and type; actions a subset; the single resource
    equal (sub-resource narrowing is not modeled in v1); every parent
    constraint still present and not loosened (child may ADD constraint
    keys -- restriction); child expiry not later than the parent's.
    """
    try:
        if child["type"] != parent["type"]:
            return False
        if child["tool"] != parent["tool"]:
            return False
        if not set(child["actions"]) <= set(parent["actions"]):
            return False
        if _single_resource(child) != _single_resource(parent):
            return False
        for key, parent_v in parent["constraints"].items():
            if key not in child["constraints"]:
                return False
            if not _constraint_narrows(child["constraints"][key],
                                       parent_v):
                return False
        child_exp = _parse_time(child["expires_at"], "expires_at")
        parent_exp = _parse_time(parent["expires_at"], "expires_at")
        if child_exp > parent_exp:
            return False
        return True
    except (GrantError, KeyError, TypeError, ValueError):
        return False


def _strictly_narrows(child, parent):
    """Strict narrowing for ``derive()``: at least one dimension must
    actually shrink (a rights copy is a caller error, not a delegation)."""
    if not narrows(child, parent):
        return False
    if set(child["actions"]) < set(parent["actions"]):
        return True
    for key, parent_v in parent["constraints"].items():
        child_v = child["constraints"][key]
        if isinstance(parent_v, (int, float)) and not isinstance(
                parent_v, bool):
            if child_v < parent_v:
                return True
        elif isinstance(parent_v, list):
            if set(child_v) < set(parent_v):
                return True
    if set(child["constraints"]) - set(parent["constraints"]):
        return True  # a brand-new restriction narrows
    child_exp = _parse_time(child["expires_at"], "expires_at")
    parent_exp = _parse_time(parent["expires_at"], "expires_at")
    if child_exp < parent_exp:
        return True
    return False


# ---------------------------------------------------------------------------
# Issuance and delegation.
# ---------------------------------------------------------------------------


def issue(tool, actions, resource, issuer_key_id, issuer_seed,
          audience, constraints=None, identifier=None, privileges=None,
          ttl_seconds=1800, parent=None, issued_at=None):
    """Mint and seal a grant (the resource owner, or a delegator, signs).

    ``issuer_seed`` is the 32-byte Ed25519 seed of ``issuer_key_id``.
    ``parent`` is the parent grant dict for delegations (its digest is
    linked). Returns the sealed grant dict.
    """
    now = issued_at or datetime.now(timezone.utc)
    grant = {
        "type": GRANT_TYPE,
        "tool": tool,
        "actions": list(actions),
        "resources": resource,
        "constraints": dict(constraints or {}),
        "identifier": identifier or ("g-" + grant_digest({
            "tool": tool, "actions": list(actions), "resources": resource,
            "issuer": issuer_key_id, "audience": audience,
            "at": now.isoformat()})[:12]),
        "privileges": list(privileges or []),
        "issued_at": now.isoformat(),
        "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
        "issuer": issuer_key_id,
        "audience": audience,
        "parent": grant_digest(parent) if parent is not None else None,
    }
    _check_shape_unsigned(grant)
    _check_times(grant, now)
    msg = canonical_bytes(grant)
    grant["signature"] = _ed_sign(bytes(issuer_seed), msg).hex()
    return grant


def _check_shape_unsigned(grant):
    """Shape check without the signature field (used at issuance, before
    sealing)."""
    probe = dict(grant)
    probe["signature"] = "00" * 64
    _check_shape(probe)


def derive(parent_grant, actions=None, constraints=None, audience=None,
           issuer_key_id=None, issuer_seed=None, ttl_seconds=None,
           identifier=None, issued_at=None):
    """Mint a narrowed child grant delegating ``parent_grant``.

    Fail-fast: a child that is not STRICTLY narrower than its parent
    refuses ``grantneg-widening-refused`` at construction -- delegation
    means narrowing.
    """
    now = issued_at or datetime.now(timezone.utc)
    parent_actions = set(parent_grant["actions"])
    child = {
        "type": parent_grant["type"],
        "tool": parent_grant["tool"],
        "actions": list(actions) if actions is not None
        else list(parent_grant["actions"]),
        "resources": parent_grant["resources"],
        "constraints": dict(constraints) if constraints is not None
        else dict(parent_grant["constraints"]),
        "identifier": identifier or (str(parent_grant["identifier"]) + "/d"),
        "privileges": list(parent_grant.get("privileges", [])),
        "issued_at": now.isoformat(),
        "expires_at": parent_grant["expires_at"],
        "issuer": issuer_key_id or parent_grant["issuer"],
        "audience": audience or parent_grant["audience"],
        "parent": grant_digest(parent_grant),
    }
    if ttl_seconds is not None:
        issued = _parse_time(child["issued_at"], "issued_at")
        child["expires_at"] = (
            issued + timedelta(seconds=ttl_seconds)).isoformat()
    if not _strictly_narrows(child, parent_grant):
        raise GrantWideningRefusedError(
            "derived grant is not strictly narrower than its parent "
            "(delegation must narrow; a rights copy is not a delegation)")
    if issuer_seed is None:
        raise GrantMalformedError(
            "derive() needs the delegator's issuer_seed to seal the child")
    msg = canonical_bytes(child)
    child["signature"] = _ed_sign(bytes(issuer_seed), msg).hex()
    # Re-verify what we just built (construction-time red check).
    _check_shape(child)
    return child


# ---------------------------------------------------------------------------
# Verification.
# ---------------------------------------------------------------------------


def verify(grant, pubkeys, now=None):
    """Verify a single grant: shape -> product-of-fields -> TTL bounds ->
    signature -> expiry. Returns the grant on success; raises the coded
    ``GrantError`` otherwise. (Anchor and audience are chain-level and
    checked by ``verify_chain``.)"""
    now = now or datetime.now(timezone.utc)
    _check_shape(grant)
    _check_times(grant, now)
    _check_signature(grant, pubkeys)
    return grant


def verify_chain(grants, pubkeys, owner_key_id, presenter, now=None):
    """Verify a delegation chain end to end (UCAN discipline).

    Checks, in order: every link verifies (shape, product-of-fields,
    TTL, signature, expiry); the first link is a root (``parent`` None);
    parent linkage (each link's ``parent`` equals the previous link's
    digest); every hop equal-or-narrower (``grantneg-chain-widened``);
    the root issuer is the tool's registered resource owner
    (``grantneg-anchor-untrusted``); the final link's audience matches
    the presenter (``grantneg-audience-mismatch``).

    Returns an audit record ``{"chain_length", "root_grant_id",
    "hops"}``. Raises the coded ``GrantError`` on any failure.
    """
    now = now or datetime.now(timezone.utc)
    if not isinstance(grants, list) or not grants:
        raise GrantMalformedError("grant chain must be a non-empty list")
    for link in grants:
        _check_shape(link)
        _check_times(link, now)
        _check_signature(link, pubkeys)
    if grants[0]["parent"] is not None:
        raise GrantMalformedError(
            "chain must start at a root grant (parent None)")
    for prev, link in zip(grants, grants[1:]):
        if link["parent"] != grant_digest(prev):
            raise GrantChainUnverifiableError(
                "chain linkage broken at grant %r: parent digest mismatch"
                % (link["identifier"],))
        if not narrows(link, prev):
            raise GrantChainWidenedError(
                "delegation hop %r is not equal-or-narrower than its "
                "parent" % (link["identifier"],))
    if grants[0]["issuer"] != owner_key_id:
        raise GrantAnchorUntrustedError(
            "chain root issuer %r is not the registered resource owner "
            "%r" % (grants[0]["issuer"], owner_key_id))
    if grants[-1]["audience"] != presenter:
        raise GrantAudienceMismatchError(
            "grant audience %r does not match presenter %r"
            % (grants[-1]["audience"], presenter))
    return {
        "chain_length": len(grants),
        "root_grant_id": grants[0]["identifier"],
        "hops": [g["identifier"] for g in grants],
    }


# ---------------------------------------------------------------------------
# Deployment-owned registry (tool registration + key directory +
# AS-metadata-style advertisement).
# ---------------------------------------------------------------------------


class GrantRegistry(object):
    """Deployment-owned registry: which tools accept grants, who owns
    them, which grant types they accept, and the known issuer keys.

    Registration is explicit and additive -- no tool is registered by
    default, so the advisory layer can never engage on a tool the
    deployment did not opt in.
    """

    def __init__(self):
        self._tools = {}
        self._keys = {}

    def register_tool(self, tool, owner_key_id,
                      grant_types=(GRANT_TYPE,)):
        """Register a risky tool with its resource-owner key id and the
        grant types it accepts. Idempotent for identical parameters;
        conflicting re-registration refuses loudly (fail-closed)."""
        if not isinstance(tool, str) or not tool:
            raise ValueError("tool must be a non-empty string")
        if not isinstance(owner_key_id, str) or not owner_key_id:
            raise ValueError("owner_key_id must be a non-empty string")
        types = tuple(grant_types)
        if not types or not all(isinstance(t, str) and t for t in types):
            raise ValueError("grant_types must be a non-empty tuple of "
                             "type strings")
        entry = {"owner_key_id": owner_key_id, "grant_types": types}
        existing = self._tools.get(tool)
        if existing is not None:
            if existing != entry:
                raise ValueError(
                    "conflicting re-registration of tool %r" % (tool,))
            return
        self._tools[tool] = entry

    def register_key(self, key_id, pubkey):
        """Record a known issuer public key (bytes or hex)."""
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("key_id must be a non-empty string")
        self._keys[key_id] = _as_pubkey_bytes(pubkey)

    def get(self, tool):
        """The registration for ``tool``, or None if unregistered."""
        return self._tools.get(tool)

    def pubkeys(self):
        """The known-issuer key directory (a copy)."""
        return dict(self._keys)

    def advertise(self):
        """AS-metadata-style advertisement: the grant types each
        registered tool accepts, for tool discovery."""
        return {
            "tools": {
                tool: {
                    "authorization_details_types_supported": list(
                        reg["grant_types"]),
                    "owner_key_id": reg["owner_key_id"],
                }
                for tool, reg in sorted(self._tools.items())
            }
        }


# ---------------------------------------------------------------------------
# Advisory entry point (only-tighten).
# ---------------------------------------------------------------------------

#: Tools with a known resource-locator kwarg, mirroring the
#: ``_fingerprint_source_key`` convention in gov/executor.py (plus the
#: write/delete path tools). A grant's resource binds to the call's
#: locator for these tools; other tools skip resource binding
#: (documented residual, not silent).
_RESOURCE_KWARG = {
    "read_file": "path",
    "write_file": "path",
    "delete_file": "path",
    "api_call": "endpoint",
    "http_post": "url",
    "send_email": "to",
}


def call_resource(tool, args):
    """The call's resource locator for scope binding.

    Returns None when there is no call context (``args`` is None) or
    the tool has no known locator (binding skipped, not failed).
    Returns ``""`` when the tool has a known locator but the call
    omits it -- binding then fails closed (a call that names no
    resource cannot be covered by a single-resource grant)."""
    if args is None:
        return None
    kwarg = _RESOURCE_KWARG.get(tool)
    if kwarg is None:
        return None
    try:
        loc = str(args.get(kwarg, ""))
    except Exception:
        return None
    return loc


def advisory_check(registry, tool, grant, presenter, args=None,
                   now=None):
    """The only-tighten advisory check for the tool-call path.

    Returns ``(status, detail)`` where status is one of:

    * ``"not-applicable"`` -- no registry, or the tool is not registered:
      the caller proceeds exactly as before;
    * ``"absent"`` -- the tool is registered but no grant was presented:
      the caller proceeds exactly as before (the deterministic layer is
      canonical; advisory failures default to allow);
    * ``"verified"`` -- a grant was presented and fully verified
      (verifier-side policy AND token-side checks both passed, and the
      grant's scope covers this call);
    * ``"refused"`` -- a grant was presented and failed verification;
      ``detail`` is ``{"code", "reason"}`` and the caller must deny.

    Scope binding: the grant's tool must equal the called tool, and --
    for tools with a known resource locator -- the grant's resource
    must equal the call's locator (``grantneg-scope-mismatch``
    otherwise). A grant for another tool or resource verifies as a
    credential but does not cover this call.

    The layer can only turn allow into deny, never deny into allow.
    """
    if registry is None:
        return "not-applicable", None
    reg = registry.get(tool)
    if reg is None:
        return "not-applicable", None
    if grant is None:
        return "absent", None
    chain = grant if isinstance(grant, list) else [grant]
    for link in chain:
        if not isinstance(link, dict) or \
                link.get("type") not in reg["grant_types"]:
            return "refused", {
                "code": "grantneg-malformed",
                "reason": "grant type %r is not accepted by tool %r "
                          "(accepted: %s)"
                          % ((link.get("type") if isinstance(link, dict)
                              else None), tool,
                             ", ".join(reg["grant_types"])),
            }
    try:
        record = verify_chain(
            chain, registry.pubkeys(),
            owner_key_id=reg["owner_key_id"], presenter=presenter,
            now=now)
    except GrantError as e:
        return "refused", {"code": e.code, "reason": str(e)}
    leaf = chain[-1]
    if leaf["tool"] != tool:
        return "refused", {
            "code": "grantneg-scope-mismatch",
            "reason": "grant covers tool %r, presented for tool %r"
                      % (leaf["tool"], tool),
        }
    locator = call_resource(tool, args)
    if locator is not None and _single_resource(leaf) != locator:
        return "refused", {
            "code": "grantneg-scope-mismatch",
            "reason": "grant covers resource %r, call targets %r"
                      % (_single_resource(leaf), locator),
        }
    return "verified", record
