#!/usr/bin/env python3
"""Grant anti-widening for delegated grants.

Re-derived (nothing copied) from the convergent industry direction
(kroehl agent-action-envelope "grants refine, never extend"; S4
mandatum signed per-hop attenuation with per-link revocation): a
delegation TRANSFERS the attenuated envelope -- it never copies rights.
Every delegation step strictly narrows at least one scope dimension,
and the full attenuation chain is audited hop by hop.

Three public functions:

1. ``mint_root_grant(grant_id, scope)`` -- mints a root grant. The
   root carries no attenuation chain; it is the trust anchor of every
   delegation that descends from it.

2. ``delegate(grant, attenuation, delegation_id, revocation_endpoint=None)``
   -- produces a child grant whose scope is the parent scope narrowed
   by ``attenuation``. Rules, all fail closed with machine-readable
   codes:

   * every attenuation dimension must exist in the parent scope, and
     its value must be provably no wider than the parent's
     (set values: subset; range values: contained; scalar values: must
     be EQUAL -- a changed scalar is not provably narrower and is
     refused). A widening dimension refuses ``grant-widened`` -- never
     silently accepted;
   * the attenuation must STRICTLY narrow at least one dimension. An
     attenuation identical to the parent scope is a rights copy, not a
     delegation, and refuses ``grant-attenuation-gap``;
   * the parent's ``grant_digest`` is re-verified before delegation: a
     tampered parent refuses ``grant-malformed``.

   The child grant carries the full ``attenuation_chain``: each hop
   records the delegation id, the parent scope, the narrowing asserted
   at that hop, the child scope, the scope digests, and the hop digest.
   The parent grant object is never mutated.

3. ``verify_delegation_chain(child, revocation_registry=None)`` --
   verifies the WHOLE chain, never just the leaf, and returns an audit
   record ``{"chain_length", "hops", "root_grant_id"}`` naming the
   narrowing asserted at every hop. Checks, in order: shape; chain
   presence (a grant with no chain refuses ``grant-chain-required``);
   the child's ``grant_digest``; per-hop digest integrity and
   parent/child continuity; revocation (an optional registry -- a
   mapping ``{hop_digest: truthy}`` or a callable
   ``hop_digest -> bool`` -- refusing ``grant-revoked`` and NAMING the
   revoked hop's index and delegation id); then the narrowing is
   re-derived at every hop (a widening hop refuses ``grant-widened``;
   a non-narrowing hop refuses ``grant-attenuation-gap``).

Stdlib only. No network. Deterministic: all digests are SHA-256 over
canonical JSON (sorted keys, compact separators); no clock, no
randomness.

Honest residuals (NOT claimed by this module): the module detects
edits to presented digests and widening attempts, not lies told
consistently from the start (a fabricated root with a self-consistent
chain verifies -- the root's authority is deployment-established);
revocation is only as current as the registry the verifier supplies
(``revocation_endpoint`` is carried as informational wiring for that
registry); scope semantics beyond the three value kinds (set, range,
scalar) are refused as malformed rather than interpreted.
"""

import hashlib
import json

# ----------------------------------------------------------------------
# Error vocabulary. The base class carries no string ``code`` (deliberate:
# the w228 refusal-vocabulary scanner must see only real product codes).
# ----------------------------------------------------------------------


class GrantAttenuationError(Exception):
    """Base class for all grant-attenuation refusals. Subclasses set
    the machine-readable ``code``."""

    code = None


class _Widened(GrantAttenuationError):
    code = "grant-widened"


class _AttenuationGap(GrantAttenuationError):
    code = "grant-attenuation-gap"


class _Revoked(GrantAttenuationError):
    code = "grant-revoked"


class _ChainRequired(GrantAttenuationError):
    code = "grant-chain-required"


class _Malformed(GrantAttenuationError):
    code = "grant-malformed"


# ----------------------------------------------------------------------
# Canonical digest helpers.
# ----------------------------------------------------------------------


def _deepcopy_jsonable(obj):
    """Decouple caller-owned objects from sealed records (scope dicts
    contain only JSON kinds, so a JSON round trip is exact)."""
    return json.loads(json.dumps(obj))


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _digest(obj):
    return hashlib.sha256(_canonical(obj)).hexdigest()


# ----------------------------------------------------------------------
# Scope model. A scope is a dict: dimension name -> value, where a value
# is one of:
#   * a list of strings (set semantics: membership);
#   * {"min": x, "max": y} with numeric x <= y (a numeric range);
#   * a scalar (string/number/bool): an exact claim, never narrowed by
#     change -- a changed scalar is refused as widening.
# ----------------------------------------------------------------------

_RANGE_KEYS = ("min", "max")


def _is_range(value):
    return (isinstance(value, dict)
            and set(value.keys()) == set(_RANGE_KEYS)
            and isinstance(value["min"], (int, float))
            and not isinstance(value["min"], bool)
            and isinstance(value["max"], (int, float))
            and not isinstance(value["max"], bool)
            and value["min"] <= value["max"])


def _is_scope_value(value):
    if isinstance(value, list):
        return all(isinstance(v, str) for v in value)
    if _is_range(value):
        return True
    return isinstance(value, (str, int, float, bool)) or value is None


def _check_scope_shape(scope, where):
    if not isinstance(scope, dict) or not scope:
        raise _Malformed("grant %s: scope must be a non-empty dict"
                         % (where,))
    for dim, value in scope.items():
        if not isinstance(dim, str) or not dim:
            raise _Malformed("grant %s: scope dimension names must be "
                             "non-empty strings" % (where,))
        if not _is_scope_value(value):
            raise _Malformed("grant %s: dimension %r has an unsupported "
                             "value shape (want list-of-str, range, or "
                             "scalar)" % (where, dim))


def _narrowing_status(parent_scope, attenuation):
    """Classify an attenuation against its parent scope.

    Returns (status, detail) where status is one of:
      "narrow"    -- every dimension narrows, and at least one does so
                     strictly;
      "copy"      -- every dimension is equal (no strict narrowing);
      "widen"     -- detail is the widened dimension name;
      "malformed" -- detail is the incomparable dimension name, or None
                     when the attenuation itself is not a dict.
    """
    if not isinstance(attenuation, dict):
        return ("malformed", None)
    strict = False
    for dim, att_val in attenuation.items():
        if dim not in parent_scope:
            return ("widen", dim)
        par_val = parent_scope[dim]
        if isinstance(par_val, list) and isinstance(att_val, list):
            if not all(isinstance(v, str) for v in att_val):
                return ("malformed", dim)
            if not set(att_val) <= set(par_val):
                return ("widen", dim)
            if set(att_val) < set(par_val):
                strict = True
        elif _is_range(par_val) and _is_range(att_val):
            if not (att_val["min"] >= par_val["min"]
                    and att_val["max"] <= par_val["max"]):
                return ("widen", dim)
            if (att_val["min"] > par_val["min"]
                    or att_val["max"] < par_val["max"]):
                strict = True
        elif (isinstance(par_val, (str, int, float, bool)) or par_val is None) \
                and (isinstance(att_val, (str, int, float, bool)) or att_val is None):
            # A scalar change is not provably narrower: it could smuggle
            # a different right. Only exact confirmation narrows.
            if type(att_val) is not type(par_val) or att_val != par_val:
                return ("widen", dim)
        else:
            return ("malformed", dim)
    if not strict:
        return ("copy", None)
    return ("narrow", None)


def _apply(parent_scope, attenuation):
    child = dict(parent_scope)
    for dim, att_val in attenuation.items():
        child[dim] = att_val
    return child


def _check_grant_shape(grant, where):
    if not isinstance(grant, dict):
        raise _Malformed("grant %s: grant must be a dict" % (where,))
    for key in ("v", "grant_id", "scope", "parent_grant_id",
                "root_grant_id", "attenuation_chain", "grant_digest"):
        if key not in grant:
            raise _Malformed("grant %s: missing key %r" % (where, key))
    if grant["v"] != 1:
        raise _Malformed("grant %s: unsupported version %r"
                         % (where, grant["v"]))
    if not isinstance(grant["grant_id"], str) or not grant["grant_id"]:
        raise _Malformed("grant %s: grant_id must be a non-empty string"
                         % (where,))
    _check_scope_shape(grant["scope"], where)
    chain = grant["attenuation_chain"]
    if not isinstance(chain, list):
        raise _Malformed("grant %s: attenuation_chain must be a list"
                         % (where,))
    return chain


def _grant_digest_of(grant):
    body = {k: v for k, v in grant.items() if k != "grant_digest"}
    return _digest(body)


def _verify_grant_digest(grant, where):
    digest = grant.get("grant_digest")
    if not isinstance(digest, str) or _grant_digest_of(grant) != digest:
        raise _Malformed("grant %s: grant_digest does not match the "
                         "grant body" % (where,))


_HOP_KEYS = ("delegation_id", "parent_grant_id", "child_grant_id",
             "parent_scope", "narrowing", "child_scope",
             "parent_scope_digest", "child_scope_digest",
             "revocation_endpoint", "hop_digest")


def _check_hop_shape(hop, where):
    if not isinstance(hop, dict):
        raise _Malformed("hop %s: hop must be a dict" % (where,))
    for key in _HOP_KEYS:
        if key not in hop:
            raise _Malformed("hop %s: missing key %r" % (where, key))
    _check_scope_shape(hop["parent_scope"], "hop %s parent" % (where,))
    _check_scope_shape(hop["child_scope"], "hop %s child" % (where,))
    if not isinstance(hop["narrowing"], dict):
        raise _Malformed("hop %s: narrowing must be a dict" % (where,))
    if _digest(hop["parent_scope"]) != hop["parent_scope_digest"]:
        raise _AttenuationGap("hop %s: parent_scope_digest does not match "
                              "the recorded parent scope" % (where,))
    if _digest(hop["child_scope"]) != hop["child_scope_digest"]:
        raise _AttenuationGap("hop %s: child_scope_digest does not match "
                              "the recorded child scope" % (where,))
    body = {k: v for k, v in hop.items() if k != "hop_digest"}
    if not isinstance(hop["hop_digest"], str) \
            or _digest(body) != hop["hop_digest"]:
        raise _AttenuationGap("hop %s: hop_digest does not match the hop "
                              "body" % (where,))


# ----------------------------------------------------------------------
# Public API.
# ----------------------------------------------------------------------


def mint_root_grant(grant_id, scope):
    """Mint a root grant: the trust anchor of a delegation tree.

    The root carries an empty attenuation chain. Its authority is
    deployment-established -- this module records the claim, it does
    not create the authority.
    """
    if not isinstance(grant_id, str) or not grant_id:
        raise _Malformed("mint: grant_id must be a non-empty string")
    _check_scope_shape(scope, "mint")
    scope = _deepcopy_jsonable(scope)
    grant = {
        "v": 1,
        "grant_id": grant_id,
        "scope": scope,
        "parent_grant_id": None,
        "root_grant_id": grant_id,
        "attenuation_chain": [],
    }
    grant["grant_digest"] = _grant_digest_of(grant)
    return grant


def delegate(grant, attenuation, delegation_id, revocation_endpoint=None):
    """Delegate a grant under an attenuation, transferring the
    attenuated envelope -- never copying rights.

    The child scope is the parent scope narrowed by ``attenuation``.
    A widening attenuation refuses ``grant-widened``; an attenuation
    that narrows nothing refuses ``grant-attenuation-gap``; a tampered
    parent refuses ``grant-malformed``.
    """
    if not isinstance(delegation_id, str) or not delegation_id:
        raise _Malformed("delegate: delegation_id must be a non-empty string")
    if revocation_endpoint is not None and not isinstance(
            revocation_endpoint, str):
        raise _Malformed("delegate: revocation_endpoint must be a string "
                         "or None")
    _check_grant_shape(grant, "delegate parent")
    _verify_grant_digest(grant, "delegate parent")
    status, dim = _narrowing_status(grant["scope"], attenuation)
    if status == "malformed":
        raise _Malformed("delegate: attenuation dimension %r is "
                         "incomparable with the parent scope" % (dim,))
    if status == "widen":
        raise _Widened("delegate: attenuation widens parent dimension "
                       "%r; grants refine, never extend" % (dim,))
    if status == "copy":
        raise _AttenuationGap("delegate: attenuation narrows nothing; a "
                              "delegation transfers an attenuated envelope, "
                              "it never copies rights")
    child_scope = _apply(_deepcopy_jsonable(grant["scope"]),
                        _deepcopy_jsonable(attenuation))
    hop = {
        "delegation_id": delegation_id,
        "parent_grant_id": grant["grant_id"],
        "child_grant_id": delegation_id,
        "parent_scope": _deepcopy_jsonable(grant["scope"]),
        "narrowing": _deepcopy_jsonable(attenuation),
        "child_scope": child_scope,
        "parent_scope_digest": _digest(grant["scope"]),
        "child_scope_digest": _digest(child_scope),
        "revocation_endpoint": revocation_endpoint,
    }
    hop_body = {k: v for k, v in hop.items() if k != "hop_digest"}
    hop["hop_digest"] = _digest(hop_body)
    child = {
        "v": 1,
        "grant_id": delegation_id,
        "scope": _deepcopy_jsonable(child_scope),
        "parent_grant_id": grant["grant_id"],
        "root_grant_id": grant["root_grant_id"],
        "attenuation_chain": list(grant["attenuation_chain"]) + [hop],
    }
    child["grant_digest"] = _grant_digest_of(child)
    return child


def _is_revoked(registry, hop_digest):
    if registry is None:
        return False
    if callable(registry):
        return bool(registry(hop_digest))
    if isinstance(registry, dict):
        return bool(registry.get(hop_digest))
    raise TypeError("revocation_registry must be None, a mapping, or a "
                    "callable")


def verify_delegation_chain(child, revocation_registry=None):
    """Verify the WHOLE delegation chain, never just the leaf.

    Returns an audit record ``{"chain_length", "hops", "root_grant_id"}``
    naming the narrowing asserted at every hop. Refusals, in check
    order: ``grant-chain-required`` (no chain to audit),
    ``grant-malformed`` (shape/digest), ``grant-attenuation-gap``
    (digest or continuity mismatch, or a hop that narrows nothing),
    ``grant-revoked`` (a hop named in the revocation registry -- the
    refusal names the hop index and delegation id),
    ``grant-widened`` (a hop whose re-derived narrowing widens).
    """
    if not isinstance(child, dict):
        raise _Malformed("verify: child must be a dict")
    chain = child.get("attenuation_chain")
    if not isinstance(chain, list) or not chain:
        raise _ChainRequired("verify: the presented grant carries no "
                             "attenuation chain; a leaf alone is not "
                             "auditable")
    _check_grant_shape(child, "verify child")
    _verify_grant_digest(child, "verify child")
    # Pass 1: shape, digests, continuity.
    for i, hop in enumerate(chain):
        where = "hop %d" % (i,)
        _check_hop_shape(hop, where)
        if hop["child_grant_id"] != hop["delegation_id"]:
            raise _AttenuationGap(
                "%s: child_grant_id %r does not match the hop's own "
                "delegation id %r" % (where, hop["child_grant_id"],
                                       hop["delegation_id"]))
        if i > 0:
            prev = chain[i - 1]
            if hop["parent_grant_id"] != prev["child_grant_id"]:
                raise _AttenuationGap(
                    "%s: parent_grant_id %r does not continue hop %d's "
                    "child_grant_id %r" % (where, hop["parent_grant_id"],
                                           i - 1, prev["child_grant_id"]))
            if hop["parent_scope"] != prev["child_scope"]:
                raise _AttenuationGap(
                    "%s: parent scope does not continue hop %d's child "
                    "scope" % (where, i - 1))
    if chain[-1]["child_scope"] != child["scope"]:
        raise _AttenuationGap("verify: final hop child scope does not "
                              "match the presented grant scope")
    if chain[-1]["child_grant_id"] != child["grant_id"]:
        raise _AttenuationGap("verify: final hop child_grant_id does not "
                              "match the presented grant_id")
    # Pass 2: revocation over the whole chain.
    for i, hop in enumerate(chain):
        if _is_revoked(revocation_registry, hop["hop_digest"]):
            raise _Revoked("verify: hop %d (delegation %r) is revoked; "
                           "the chain is not releasable"
                           % (i, hop["delegation_id"]))
    # Pass 3: re-derive the narrowing at every hop.
    hops_audit = []
    for i, hop in enumerate(chain):
        where = "hop %d" % (i,)
        status, dim = _narrowing_status(hop["parent_scope"], hop["narrowing"])
        if status == "malformed":
            raise _Malformed("%s: narrowing dimension %r is incomparable "
                             "with the parent scope" % (where, dim))
        if status == "widen":
            raise _Widened("%s: narrowing widens parent dimension %r; "
                           "grants refine, never extend" % (where, dim))
        if status == "copy":
            raise _AttenuationGap("%s: the hop narrows nothing; a "
                                  "delegation transfers an attenuated "
                                  "envelope, it never copies rights"
                                  % (where,))
        if _apply(hop["parent_scope"], hop["narrowing"]) != hop["child_scope"]:
            raise _AttenuationGap("%s: recorded child scope is not the "
                                  "parent scope narrowed by the recorded "
                                  "narrowing" % (where,))
        hops_audit.append({
            "index": i,
            "delegation_id": hop["delegation_id"],
            "narrowing": dict(hop["narrowing"]),
            "hop_digest": hop["hop_digest"],
        })
    return {
        "chain_length": len(chain),
        "hops": hops_audit,
        "root_grant_id": child["root_grant_id"],
    }
