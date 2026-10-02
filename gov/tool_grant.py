"""Per-Tool Grants (PTG) for MCP tool authorization.

The MCP python-sdk performs OAuth at the server level and never maps a
scope to a *tool*: once a session is authenticated, ``tools/call`` runs
with no per-tool check (wave-269 prospectus, verified at source). This
module is Sasanam's answer: a signed, attenuable, key-bound grant that
authorizes exactly one (server, tool, argument-shape) at a time.

Design sources (all pattern-only, nothing copied):

- RFC 9396 ``authorization_details`` -- the per-tool grammar: ``type`` /
  ``locations`` / ``actions`` / ``identifier`` / ``privileges``, one
  tool per object, identifier matched byte-for-byte (wave-177 exact
  matching precedent). ``type`` is the URI-namespaced ASCII value
  ``https://sasanam.dev/mcp_tool_call``.
- RFC 8693 token exchange + ``act`` -- broad-to-narrow attenuation at
  delegation boundaries; delegation (not impersonation); access-control
  consumers consider ONLY top-level claims -- nested ``act`` is
  informational and is never consulted by enforcement (by construction:
  this module never reads nested ``act``).
- Macaroons -- offline attenuation: a grant holder appends further
  first-party caveats (tighter bounds, fewer calls, shorter window)
  signed over the chain, verifiable by the gateway with no AS
  round-trip. Verifier discipline is structural: the caveat/predicate
  registry is CLOSED and versioned; an unrecognized predicate fails
  closed, never skipped.
- RFC 9449 DPoP -- each grant is bound to the workload's proof key via
  a ``cnf`` JWK thumbprint; the caller presents a fresh per-call proof
  signed by that key over the grant digest + method + URI + timestamp.
  A grant exfiltrated from one workload cannot be replayed by another.
- RFC 8707 resource indicators -- single ``aud`` (a string, never a
  list); audience answers "which server may accept this", never "which
  tool on that server may run".
- SPIFFE JWT-SVID -- ``sub`` is the workload identity (SPIFFE-ID
  shaped, deployment-issued); per-tool claims are deployment-added by
  definition -- that deployment is this issuer.
- Zanzibar -- grants bind to ``mandate_version`` (the zookie analog);
  enforcement fails closed on version drift.

Enforcement point: the MCP tool gateway's syntactic-quarantine stage,
post-parse -- the grant is checked against the canonicalized arguments
*before* the tool call is assembled.

Revocation: primary = short TTL + ``max_calls`` (one-shot grants);
secondary = introspection hook (``grant_status``); tertiary = mandate
kill (bumping ``mandate_version`` invalidates derived grants at next
enforcement). Honest statement: without an online introspection check
there is a stale window equal to the TTL; Sasanam documents the window
per tool-risk-class instead of claiming instant global revocation.

The RFC 8693 trap is carried, not hidden: exchanging a parent grant for
a narrower child does NOT revoke the parent. ``exchange()`` returns the
child and documents that the parent remains valid until it expires.

Determinism: canonical JSON (sort_keys, compact separators,
ensure_ascii); every time-taking function takes an explicit ``now``;
never ambient clock, never randomness (``jti`` defaults to a digest of
the canonical body).
"""
import base64
import hashlib
import json
import re

from gov import decoy_grants
from gov import ed25519

GRANT_TYPE = "https://sasanam.dev/mcp_tool_call"
GRANT_ISSUER = "sasanam-tool-as"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.\-]+::[A-Za-z0-9_.\-]+$")
_SPIFFE_RE = re.compile(r"^spiffe://[A-Za-z0-9_.\-/]+$")
_PROOF_SKEW_S = 60
_MAX_LIFETIME_S = 3600

# ---------------------------------------------------------------------------
# Decision codes (ptgrant domain; merged taxonomy pin 1493)
# ---------------------------------------------------------------------------

PTGRANT_CODES = [
    # --- v2 enforcement refinement (wave-271, 6 codes) ---
    # Missing required arg_bounds attribute at the seam: deny + log the
    # missing fields (never a conditional permission, SpiceDB lesson).
    "ptgrant-arg-attribute-missing",
    "ptgrant-arg-bound-violated",
    "ptgrant-attenuation-invalid",
    "ptgrant-audience-mismatch",
    # Per-request tool cap exceeded on a batch evaluation.
    "ptgrant-batch-tool-cap-exceeded",
    # Caller credential lacks the required scope for the operation.
    "ptgrant-caller-unauthorized",
    "ptgrant-cnf-missing",
    # Request-scoped context material exceeds the size cap.
    "ptgrant-context-oversize",
    "ptgrant-grant-expired",
    "ptgrant-grant-malformed",
    "ptgrant-grant-not-yet-valid",
    "ptgrant-invalid-target",
    "ptgrant-issuer-unknown",
    "ptgrant-jti-reused",
    "ptgrant-link-unverifiable",
    "ptgrant-mandate-drift",
    # Mandate store unreachable (raise or None): fail closed.
    "ptgrant-mandate-unreachable",
    "ptgrant-max-calls-exhausted",
    "ptgrant-ok",
    "ptgrant-pop-invalid",
    # Grant's pinned predicate-registry hash != registry under evaluation.
    "ptgrant-predicate-hash-mismatch",
    "ptgrant-predicate-unknown",
    "ptgrant-signature-invalid",
    "ptgrant-supply-chain-failed",
    "ptgrant-tool-not-covered",
]


class GrantError(Exception):
    """Machine-coded grant failure. Carries ``.code`` and ``.detail``."""

    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Decoy-grant defaults (wave-276)
# ---------------------------------------------------------------------------
# The decoy canary is ON by default: omitting ``decoy_registry`` selects
# the default registry (gov.decoy_grants.DEFAULT_DECOY_TOOLS). Passing
# ``decoy_registry=None`` explicitly disables decoy handling (legacy,
# byte-identical behavior). A deployment whose real tools collide with
# decoy names disables or customizes the registry -- a loud, conscious
# choice, never a silent one.
_DECOY_DEFAULT = object()
_DEFAULT_DECOY_REGISTRY = decoy_grants.DecoyRegistry()


def _resolve_decoy_registry(decoy_registry):
    """Map the decoy_registry kwarg to None | DecoyRegistry."""
    if decoy_registry is None:
        return None
    if decoy_registry is _DECOY_DEFAULT:
        return _DEFAULT_DECOY_REGISTRY
    return decoy_registry


# ---------------------------------------------------------------------------
# Canonical bytes + small helpers
# ---------------------------------------------------------------------------

def _canonical(obj):
    """Deterministic JSON bytes for signing/digesting."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


# Sentinel distinguishing "argument attribute absent" from "present with
# value None" at the v2 evaluation seam (wave-271).
_MISSING = object()


def _b64(b):
    return base64.b64encode(bytes(b)).decode("ascii")


def _unb64(s):
    try:
        return base64.b64decode(s.encode("ascii"))
    except Exception:  # noqa: BLE001
        return None


def _jwk_thumbprint(pub):
    """RFC 7638 thumbprint of the Ed25519 OKP JWK for ``pub`` (32 bytes)."""
    jwk = {"crv": "Ed25519", "kty": "OKP", "x": _b64(pub)}
    return base64.urlsafe_b64encode(
        hashlib.sha256(_canonical(jwk)).digest()).decode("ascii").rstrip("=")


# ---------------------------------------------------------------------------
# Closed predicate registry (version 1)
# ---------------------------------------------------------------------------

def _p_prefix(arg, params):
    p = params.get("prefix")
    return isinstance(p, str) and isinstance(arg, str) and arg.startswith(p)


def _p_one_of(arg, params):
    vals = params.get("values")
    return isinstance(vals, list) and arg in vals


def _p_max_len(arg, params):
    m = params.get("max_len")
    if not isinstance(m, int) or isinstance(m, bool) or m < 0:
        return False
    try:
        return len(arg) <= m
    except TypeError:
        return False


def _p_max_value(arg, params):
    m = params.get("max_value")
    if isinstance(m, bool) or not isinstance(m, (int, float)):
        return False
    if isinstance(arg, bool) or not isinstance(arg, (int, float)):
        return False
    return arg <= m


def _p_regex(arg, params):
    pat = params.get("pattern")
    if not isinstance(pat, str) or not isinstance(arg, str):
        return False
    try:
        return re.search(pat, arg) is not None
    except re.error:
        return False


def _p_arg_bound(args, params):
    """Attenuation-caveat predicate: apply ``predicate`` to ``args[arg]``."""
    arg = params.get("arg")
    pred = params.get("predicate")
    sub = params.get("params")
    if not isinstance(arg, str) or not isinstance(sub, dict):
        return False
    fn = PREDICATE_REGISTRY.get(pred)
    if fn is None:
        return False
    if not isinstance(args, dict):
        return False
    return fn(args.get(arg), sub)


def _p_max_calls(_args, params):
    # Evaluated by the budget logic, not per-argument; always True here.
    return isinstance(params.get("max_calls"), int)


def _p_exp(_args, params):
    return isinstance(params.get("exp"), int)


PREDICATE_REGISTRY = {
    "prefix": _p_prefix,
    "one_of": _p_one_of,
    "max_len": _p_max_len,
    "max_value": _p_max_value,
    "regex": _p_regex,
    "arg_bound": _p_arg_bound,
    "max_calls": _p_max_calls,
    "exp": _p_exp,
}
PREDICATE_REGISTRY_VERSION = 1


def predicate_registry_hash():
    """Content hash of the closed predicate registry (SpiceDB schema-hash
    discipline): sha256 over the canonical (registry-version, sorted
    predicate-name set). The grant carries this hash in its signed body;
    enforcement refuses when the registry under evaluation differs from
    the pinned one. Predicate *implementations* are pinned by
    (version, name-set): any semantic change must ship a version bump,
    which is the deployment discipline this function enforces.
    """
    canonical = {"version": PREDICATE_REGISTRY_VERSION,
                 "predicates": sorted(PREDICATE_REGISTRY.keys())}
    return hashlib.sha256(_canonical(canonical)).hexdigest()


# zedtoken discipline: the grant body pins exactly this value at issue.
PREDICATE_REGISTRY_HASH = predicate_registry_hash()


def eval_predicate(name, arg, params):
    """Evaluate a named predicate. Unknown name or malformed params -> False."""
    fn = PREDICATE_REGISTRY.get(name)
    if fn is None or not isinstance(params, dict):
        return False
    try:
        return bool(fn(arg, params))
    except Exception:  # noqa: BLE001 -- predicates never raise
        return False


# ---------------------------------------------------------------------------
# Usage store (one-shot / max_calls bookkeeping; deployment backs durably)
# ---------------------------------------------------------------------------

class UsageStore:
    """In-memory per-jti call accounting. Deterministic.

    Honest limit: one-shot semantics are only as durable as this store.
    A deployment that needs cross-restart one-shot enforcement must back
    it with durable storage (e.g. the HMAC-chained ledger); the default
    here is process-local.
    """

    def __init__(self):
        self._used = {}
        self._nonces = set()

    def consume(self, jti, max_calls):
        """Record one call against ``jti``. Returns (ok, remaining)."""
        used = self._used.get(jti, 0)
        if used >= max_calls:
            return False, 0
        self._used[jti] = used + 1
        return True, max_calls - used - 1

    def seen_nonce(self, jti, nonce):
        """True if this (jti, nonce) proof was already presented."""
        key = (jti, nonce)
        if key in self._nonces:
            return True
        self._nonces.add(key)
        return False

    def status(self, jti, max_calls):
        used = self._used.get(jti, 0)
        return {"jti": jti, "calls_used": used, "calls_max": max_calls,
                "exhausted": used >= max_calls}


# ---------------------------------------------------------------------------
# Issuer
# ---------------------------------------------------------------------------

class Issuer:
    """The Tool Authorization Service (plays the OAuth AS).

    ``mandate_lookup(mandate_id)`` returns ``{"version": int}`` or None.
    """

    def __init__(self, iss, issuer_seed, mandate_lookup,
                 decoy_registry=_DECOY_DEFAULT):
        if iss != GRANT_ISSUER:
            raise GrantError("ptgrant-issuer-unknown",
                             "issuer %r is not %r" % (iss, GRANT_ISSUER))
        if not isinstance(issuer_seed, (bytes, bytearray)) or len(issuer_seed) != 32:
            raise GrantError("ptgrant-grant-malformed", "issuer_seed must be 32 bytes")
        self._iss = iss
        self._seed = bytes(issuer_seed)
        self._pub = ed25519.publickey(self._seed)
        self._mandate_lookup = mandate_lookup
        # Wave-276 decoy grants: the canary is ON by default (omitted ->
        # default registry). ``decoy_registry=None`` explicitly disables
        # the mint refusal. The issuer never mints for decoy identifiers
        # unless the deployment consciously opts out.
        self._decoy_registry = _resolve_decoy_registry(decoy_registry)

    @property
    def issuer_pub(self):
        return self._pub

    def _check_mandate(self, mandate_id, mandate_version):
        m = self._mandate_lookup(mandate_id)
        if m is None or m.get("version") != mandate_version:
            raise GrantError("ptgrant-invalid-target",
                             "mandate %r at version %r is not current"
                             % (mandate_id, mandate_version))
        return m

    @staticmethod
    def _check_details(details):
        if not isinstance(details, list) or not details:
            raise GrantError("ptgrant-grant-malformed",
                             "details must be a non-empty list")
        seen = set()
        for d in details:
            if not isinstance(d, dict):
                raise GrantError("ptgrant-grant-malformed", "detail must be an object")
            if d.get("type") != GRANT_TYPE:
                raise GrantError("ptgrant-grant-malformed",
                                 "detail type must be %r" % (GRANT_TYPE,))
            ident = d.get("identifier")
            if not isinstance(ident, str) or not _IDENTIFIER_RE.match(ident):
                raise GrantError("ptgrant-grant-malformed",
                                 "identifier %r is not server::tool" % (ident,))
            if ident in seen:
                raise GrantError("ptgrant-grant-malformed",
                                 "duplicate identifier %r" % (ident,))
            seen.add(ident)
            locs = d.get("locations")
            if not isinstance(locs, list) or not locs or not all(
                    isinstance(x, str) and x.startswith("https://") for x in locs):
                raise GrantError("ptgrant-grant-malformed",
                                 "locations must be non-empty https URIs")
            if d.get("actions") != ["call"]:
                raise GrantError("ptgrant-grant-malformed",
                                 "v1 supports actions == [\"call\"] only")
            bounds = d.get("arg_bounds", {})
            if not isinstance(bounds, dict):
                raise GrantError("ptgrant-grant-malformed", "arg_bounds must be an object")
            for arg, b in bounds.items():
                if not isinstance(b, dict) or b.get("predicate") not in PREDICATE_REGISTRY:
                    raise GrantError("ptgrant-predicate-unknown",
                                     "arg_bounds[%r] uses unknown predicate" % (arg,))
                if not isinstance(b.get("params"), dict):
                    raise GrantError("ptgrant-grant-malformed",
                                     "arg_bounds[%r] needs params object" % (arg,))
            sc = d.get("supply_chain", {})
            ld = sc.get("link_digest") if isinstance(sc, dict) else None
            if not isinstance(ld, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", ld):
                raise GrantError("ptgrant-grant-malformed",
                                 "supply_chain.link_digest must be sha256:<64 hex>")
            mc = d.get("max_calls")
            if not isinstance(mc, int) or isinstance(mc, bool) or mc < 1:
                raise GrantError("ptgrant-grant-malformed",
                                 "max_calls must be a positive int")

    def issue(self, *, sub, aud, proof_pub, mandate_id, mandate_version,
              details, lifetime_s, now, act=None, jti=None):
        """Mint a Per-Tool Grant. Every refusal raises GrantError."""
        if not isinstance(sub, str) or not _SPIFFE_RE.match(sub):
            raise GrantError("ptgrant-grant-malformed",
                             "sub must be a SPIFFE-ID-shaped workload identity")
        if not isinstance(aud, str) or not aud.startswith("https://"):
            raise GrantError("ptgrant-audience-mismatch",
                             "aud must be a single https URI (RFC 8707 discipline)")
        if not isinstance(proof_pub, (bytes, bytearray)) or len(proof_pub) != 32:
            raise GrantError("ptgrant-cnf-missing",
                             "proof_pub must be the 32-byte workload proof key")
        self._check_mandate(mandate_id, mandate_version)
        self._check_details(details)
        if self._decoy_registry is not None:
            for d in details:
                ident = d.get("identifier") if isinstance(d, dict) else None
                if self._decoy_registry.is_decoy_identifier(ident):
                    raise GrantError(
                        decoy_grants.DECOY_MINT_REFUSAL_CODE,
                        "identifier %r is a registered decoy: "
                        "grants for decoy tools are never minted" % (ident,))
        if (not isinstance(lifetime_s, int) or isinstance(lifetime_s, bool)
                or not 1 <= lifetime_s <= _MAX_LIFETIME_S):
            raise GrantError("ptgrant-grant-malformed",
                             "lifetime_s must be 1..%d" % _MAX_LIFETIME_S)
        if not isinstance(now, int) or isinstance(now, bool):
            raise GrantError("ptgrant-grant-malformed", "now must be an int epoch")
        if act is not None and not isinstance(act, dict):
            raise GrantError("ptgrant-grant-malformed", "act must be an object")
        body = {
            "iss": self._iss,
            "sub": sub,
            "aud": aud,
            "iat": now,
            "exp": now + lifetime_s,
            "mandate_id": mandate_id,
            "mandate_version": mandate_version,
            "cnf": {"jkt": _jwk_thumbprint(bytes(proof_pub))},
            "authorization_details": details,
            "predicate_registry_version": PREDICATE_REGISTRY_VERSION,
            # v2 (wave-271): zedtoken-style content-hash pin of the predicate
            # registry under which the grant was minted. Enforcement with
            # check_registry_pin=True refuses grants whose pinned hash does
            # not match the live registry, and refuses unpinned v1 grants.
            "predicate_registry_hash": predicate_registry_hash(),
        }
        if act is not None:
            # Top-level claims only: nested ``act`` is informational and is
            # never consulted by enforcement (see enforce()).
            body["act"] = act
        body["jti"] = jti if isinstance(jti, str) and jti else \
            hashlib.sha256(_canonical(body)).hexdigest()[:32]
        sig = ed25519.sign(self._seed, _canonical(body))
        return {"body": body, "sig": _b64(sig), "attenuation": []}

    def exchange(self, parent, *, parent_holder_seed, details, now,
                 proof_pub, lifetime_s, act=None):
        """RFC 8693-style attenuation ceremony: mint a narrower child grant.

        The child must be within the parent's rights (identifiers present
        in the parent, bounds narrowed, max_calls not raised, lifetime
        within the parent's remaining window). Anything outside the parent
        refuses ``ptgrant-invalid-target``.

        F285: the exchanger must prove possession of the PARENT grant's
        cnf key -- ``parent_holder_seed`` is a 32-byte seed whose derived
        key must match the parent's ``cnf.jkt`` (mirroring attenuate()'s
        discipline). Read-only access to a parent grant (logs, backups)
        must not become write access. The old ``issuer_seed`` parameter
        was REMOVED from the signature: it was silently ignored (the
        issuer always signs with its own ceremony key, ``self._seed``),
        and its name promised an authentication that never happened.

        TRAP (RFC 8693 2.1, carried honestly): exchanging does NOT revoke
        the parent. The parent remains valid until it expires.
        """
        pok, pcode, _ = verify_grant(parent, issuer_pub=self._pub, now=now)
        if not pok:
            raise GrantError(pcode, "parent grant is not valid for exchange")
        pbody = parent["body"]
        if (not isinstance(parent_holder_seed, (bytes, bytearray))
                or len(parent_holder_seed) != 32):
            raise GrantError("ptgrant-pop-invalid",
                             "parent_holder_seed must be a 32-byte seed")
        if (_jwk_thumbprint(ed25519.publickey(bytes(parent_holder_seed)))
                != pbody["cnf"]["jkt"]):
            raise GrantError("ptgrant-pop-invalid",
                             "exchanger key is not the parent grant's cnf key")
        self._check_details(details)
        pmap = {d["identifier"]: d for d in pbody["authorization_details"]}
        for d in details:
            ident = d["identifier"]
            pd = pmap.get(ident)
            if pd is None:
                raise GrantError("ptgrant-invalid-target",
                                 "identifier %r not covered by parent" % (ident,))
            if d["max_calls"] > pd["max_calls"]:
                raise GrantError("ptgrant-invalid-target",
                                 "child max_calls exceeds parent for %r" % (ident,))
            if not _bounds_narrow(pd.get("arg_bounds", {}), d.get("arg_bounds", {})):
                raise GrantError("ptgrant-invalid-target",
                                 "child arg_bounds widen parent for %r" % (ident,))
        if lifetime_s > pbody["exp"] - now:
            raise GrantError("ptgrant-invalid-target",
                             "child lifetime exceeds parent's remaining window")
        child = self.issue(
            sub=pbody["sub"], aud=pbody["aud"], proof_pub=proof_pub,
            mandate_id=pbody["mandate_id"], mandate_version=pbody["mandate_version"],
            details=details, lifetime_s=lifetime_s, now=now, act=act,
            jti="xchg-" + hashlib.sha256(_canonical(details)).hexdigest()[:27])
        return child


def _bounds_narrow(parent_bounds, child_bounds):
    """True iff every child bound narrows (or equals) the parent bound."""
    for arg, cb in child_bounds.items():
        pb = parent_bounds.get(arg)
        if pb is None:
            return False  # child constrains an arg the parent left free
        if cb.get("predicate") != pb.get("predicate"):
            return False
        cp, pp = cb.get("params", {}), pb.get("params", {})
        pred = cb.get("predicate")
        if pred == "prefix":
            if not (isinstance(cp.get("prefix"), str) and isinstance(pp.get("prefix"), str)
                    and cp["prefix"].startswith(pp["prefix"])):
                return False
        elif pred == "one_of":
            if not (isinstance(cp.get("values"), list) and isinstance(pp.get("values"), list)
                    and set(cp["values"]) <= set(pp["values"])):
                return False
        elif pred == "max_len":
            if not (isinstance(cp.get("max_len"), int) and isinstance(pp.get("max_len"), int)
                    and cp["max_len"] <= pp["max_len"]):
                return False
        elif pred == "max_value":
            if not (isinstance(cp.get("max_value"), (int, float))
                    and isinstance(pp.get("max_value"), (int, float))
                    and cp["max_value"] <= pp["max_value"]):
                return False
        elif pred == "regex":
            if cp.get("pattern") != pp.get("pattern"):
                return False  # regex narrowing is undecidable; only equality
        else:
            return False  # only the four v1 bound predicates narrow offline
    return True


# ---------------------------------------------------------------------------
# Offline attenuation (macaroon track)
# ---------------------------------------------------------------------------

def attenuate(grant, *, holder_seed, issuer_pub, caveats):
    """Append signed first-party caveats to a grant (no AS round-trip).

    Each caveat is {"predicate": name, "params": {...}}. Records chain:
    sig_i = sign(holder, canonical({"predicate", "params", "by", "prev": sig_{i-1}})).
    ``by`` must be the holder's proof key (the grant's cnf key).
    """
    ok, code, _ = verify_grant(grant, issuer_pub=issuer_pub,
                               now=grant["body"]["iat"])
    if not ok:
        raise GrantError(code, "cannot attenuate an invalid grant")
    if not isinstance(holder_seed, (bytes, bytearray)) or len(holder_seed) != 32:
        raise GrantError("ptgrant-grant-malformed", "holder_seed must be 32 bytes")
    holder_seed = bytes(holder_seed)
    holder_pub = ed25519.publickey(holder_seed)
    if _jwk_thumbprint(holder_pub) != grant["body"]["cnf"]["jkt"]:
        raise GrantError("ptgrant-pop-invalid",
                         "attenuator key is not the grant's cnf key")
    if not isinstance(caveats, list) or not caveats:
        raise GrantError("ptgrant-grant-malformed", "caveats must be a non-empty list")
    out = {"body": grant["body"], "sig": grant["sig"],
           "attenuation": list(grant.get("attenuation", []))}
    prev = _unb64(grant["sig"]) if not out["attenuation"] else \
        _unb64(out["attenuation"][-1]["sig"])
    for c in caveats:
        if not isinstance(c, dict) or c.get("predicate") not in PREDICATE_REGISTRY:
            raise GrantError("ptgrant-predicate-unknown",
                             "caveat uses unknown predicate %r" % (c.get("predicate"),))
        if not isinstance(c.get("params"), dict):
            raise GrantError("ptgrant-grant-malformed", "caveat needs params object")
        rec = {"predicate": c["predicate"], "params": c["params"],
               "by": _b64(holder_pub), "prev": _b64(prev)}
        rec["sig"] = _b64(ed25519.sign(holder_seed, _canonical(rec)))
        prev = _unb64(rec["sig"])
        out["attenuation"].append(rec)
    return out


def _check_attenuation(grant, holder_pub):
    """Verify the attenuation chain. Returns (ok, code, detail, budget)."""
    atts = grant.get("attenuation", [])
    prev = _unb64(grant.get("sig"))
    if prev is None:
        return False, "ptgrant-attenuation-invalid", "grant sig not decodable", None
    budget = {"max_calls": None, "exp": None, "caveats": []}
    holder_b64 = _b64(holder_pub)
    for rec in atts:
        if not isinstance(rec, dict) or rec.get("by") != holder_b64:
            return False, "ptgrant-attenuation-invalid", \
                "attenuation not by the cnf key", None
        rsig = _unb64(rec.get("sig"))
        if rsig is None:
            return False, "ptgrant-attenuation-invalid", "bad record sig", None
        unsigned = {k: v for k, v in rec.items() if k != "sig"}
        if unsigned.get("prev") != _b64(prev):
            return False, "ptgrant-attenuation-invalid", "chain broken", None
        if ed25519.verify(holder_pub, _canonical(unsigned), rsig) is not True:
            return False, "ptgrant-attenuation-invalid", "record sig invalid", None
        pred = rec.get("predicate")
        if pred not in PREDICATE_REGISTRY:
            return False, "ptgrant-predicate-unknown", \
                "caveat predicate %r unknown" % (pred,), None
        if pred == "max_calls":
            mc = rec.get("params", {}).get("max_calls")
            if isinstance(mc, int) and (budget["max_calls"] is None or mc < budget["max_calls"]):
                budget["max_calls"] = mc
        elif pred == "exp":
            ex = rec.get("params", {}).get("exp")
            if isinstance(ex, int) and (budget["exp"] is None or ex < budget["exp"]):
                budget["exp"] = ex
        else:
            budget["caveats"].append(rec)
        prev = rsig
    return True, "ptgrant-ok", "", budget


# ---------------------------------------------------------------------------
# DPoP-style proof of possession
# ---------------------------------------------------------------------------

def make_pop_proof(seed, grant, *, method, uri, now, nonce=None):
    """Mint a per-call proof of possession bound to the grant's digest.

    ``nonce`` must be a non-empty string that is unique per call. There
    is no silent default: omitting it (or passing a non-string/empty
    value) is a loud ``ptgrant-pop-invalid`` refusal, never a digest
    fallback. This module is deterministic ("never randomness"), and a
    digest of (method, uri, now) collides within the same second -- two
    byte-identical proofs, the second legitimate call falsely refused as
    a replay (F254). The caller supplies per-call uniqueness.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise GrantError("ptgrant-grant-malformed", "seed must be 32 bytes")
    if not isinstance(nonce, str) or not nonce:
        raise GrantError("ptgrant-pop-invalid",
                         "nonce is required and must be a non-empty string")
    seed = bytes(seed)
    body = grant["body"]
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    proof = {
        "grant_digest": digest,
        "jti": body["jti"],
        "method": method,
        "uri": uri,
        "iat": now,
        "nonce": nonce,
        "pub": _b64(ed25519.publickey(seed)),
    }
    proof["sig"] = _b64(ed25519.sign(seed, _canonical(proof)))
    return proof


def _check_proof(proof, grant, now):
    body = grant["body"]
    if not isinstance(proof, dict):
        return False, "ptgrant-pop-invalid", "proof must be an object", None
    psig = _unb64(proof.get("sig"))
    pub = _unb64(proof.get("pub"))
    if psig is None or pub is None or len(pub) != 32:
        return False, "ptgrant-pop-invalid", "proof sig/pub malformed", None
    unsigned = {k: v for k, v in proof.items() if k != "sig"}
    if ed25519.verify(pub, _canonical(unsigned), psig) is not True:
        return False, "ptgrant-pop-invalid", "proof signature invalid", None
    if unsigned.get("grant_digest") != hashlib.sha256(
            _canonical(body)).hexdigest():
        return False, "ptgrant-pop-invalid", "proof not bound to this grant", None
    if unsigned.get("jti") != body["jti"]:
        return False, "ptgrant-pop-invalid", "proof jti mismatch", None
    if _jwk_thumbprint(pub) != body["cnf"]["jkt"]:
        return False, "ptgrant-pop-invalid", "proof key is not the cnf key", None
    iat = unsigned.get("iat")
    if not isinstance(iat, int) or abs(now - iat) > _PROOF_SKEW_S:
        return False, "ptgrant-pop-invalid", "proof outside time window", None
    return True, "ptgrant-ok", "", pub


# ---------------------------------------------------------------------------
# Verification (offline) + gateway enforcement
# ---------------------------------------------------------------------------

def verify_grant(grant, *, issuer_pub, now):
    """Offline grant validity: shape + signature + time window."""
    try:
        body = grant["body"]
        sig = _unb64(grant.get("sig"))
        if not isinstance(body, dict) or sig is None or len(sig) != 64:
            return False, "ptgrant-grant-malformed", {}
        for f in ("iss", "sub", "aud", "iat", "exp", "jti", "mandate_id",
                  "mandate_version", "cnf", "authorization_details"):
            if f not in body:
                return False, "ptgrant-grant-malformed", {}
        if body["iss"] != GRANT_ISSUER:
            return False, "ptgrant-issuer-unknown", {}
        if ed25519.verify(issuer_pub, _canonical(body), sig) is not True:
            return False, "ptgrant-signature-invalid", {}
        if not isinstance(body["exp"], int) or not isinstance(body["iat"], int):
            return False, "ptgrant-grant-malformed", {}
        if now >= body["exp"]:
            return False, "ptgrant-grant-expired", {}
        if now < body["iat"]:
            return False, "ptgrant-grant-not-yet-valid", {}
        return True, "ptgrant-ok", dict(body)
    except Exception:  # noqa: BLE001 -- verification never raises
        return False, "ptgrant-grant-malformed", {}


def _deny(code, detail, checked):
    return {"ok": False, "code": code, "detail": detail,
            "checked": list(checked), "grant_jti": None}


def enforce(grant, *, proof, issuer_pub, server_name, server_uri, tool, args,
            now, usage_store, mandate_version_provider, link_verifier,
            request_context=None, check_registry_pin=False,
            max_context_bytes=4096, decoy_registry=_DECOY_DEFAULT):
    """Gateway enforcement, post-parse. Never raises; fail-closed verdicts.

    Check order: shape/signature -> decoy trip (canary ON by default: the
    attempt itself is the signal, regardless of grant coverage) ->
    registry pin (v2, opt-in) -> issuer ->
    aud -> time -> PoP/cnf -> mandate version -> detail selection ->
    request context (v2, opt-in) -> arg_bounds -> attenuation ->
    supply chain -> nonce replay -> budget.

    ``decoy_registry``: a ``gov.decoy_grants.DecoyRegistry``. Omitted ->
    the default registry (canary on). ``None`` -> decoy handling
    disabled (byte-identical to the pre-decoy tree). When the invoked
    tool is a registered decoy, enforcement denies with the coded
    ``decoy-grant-tripped`` verdict and attaches the injection-evidence
    event (``verdict["decoy_trip"]``) for the gateway's audit writer.

    v2 kwargs are backward-compatible: with the defaults (``request_context``
    unset, ``check_registry_pin`` False) behavior is byte-identical to v1.
    ``request_context`` merges request-scoped invocation material into the
    evaluation view for this one check only; it is never persisted. F287:
    attenuation ``arg_bound`` caveats read the same args-then-context
    view as grant-level ``arg_bounds``.
    """
    checked = []
    ok, code, _body = verify_grant(grant, issuer_pub=issuer_pub, now=now)
    checked.append("grant:%s" % code)
    if not ok:
        return _deny(code, "grant invalid", checked)
    body = _body

    # Wave-276 decoy grants: the canary is ON by default (omitted kwarg
    # -> default registry; None -> explicitly disabled). A decoy
    # invocation is high-confidence injection evidence no matter what the
    # accompanying grant claims -- no legitimate workflow ever touches a
    # decoy, and the issuer never mints for one (so a grant purporting to
    # cover a decoy is stale or malicious). Trip before any other check:
    # the attempt itself is the signal, and the verdict stays fail-closed
    # with the evidence event attached for the gateway's audit writer.
    decoy_registry = _resolve_decoy_registry(decoy_registry)
    if decoy_registry is not None:
        trip = decoy_registry.check_invocation(server_name, tool)
        if trip is not None:
            checked.append("decoy:tripped")
            verdict = _deny(
                decoy_grants.DECOY_TRIP_CODE,
                "decoy tool %r invoked: injection canary tripped" % (tool,),
                checked)
            verdict["decoy_trip"] = decoy_grants.trip_event(
                trip, server_name=server_name, tool=tool,
                grant_jti=body.get("jti"))
            return verdict

    # v2 (wave-271, opt-in): zedtoken-style registry pin. The grant's signed
    # body carries the predicate-registry content hash under which it was
    # minted; enforcement refuses when the live registry differs, and
    # refuses unpinned (pre-v2) grants -- fail closed on verifier drift.
    if check_registry_pin:
        pinned = body.get("predicate_registry_hash")
        live = predicate_registry_hash()
        if pinned != live:
            checked.append("registry:hash-mismatch")
            return _deny("ptgrant-predicate-hash-mismatch",
                         "grant pinned to registry hash %r, registry is %r"
                         % (pinned, live), checked)
        checked.append("registry:pin-ok")

    if body["aud"] != server_uri or not isinstance(body["aud"], str):
        checked.append("aud:mismatch")
        return _deny("ptgrant-audience-mismatch",
                     "grant aud %r is not this server" % (body.get("aud"),), checked)
    checked.append("aud:ok")

    pok, pcode, pdetail, holder_pub = _check_proof(proof, grant, now)
    checked.append("pop:%s" % pcode)
    if not pok:
        return _deny(pcode, pdetail, checked)

    # F286: the provider is called unwrapped at this seam, but the
    # contract is "Never raises; fail-closed verdicts". Follow the
    # evaluate_request convention: any store failure is unreachable.
    try:
        cur = mandate_version_provider(body["mandate_id"])
    except Exception:  # noqa: BLE001 -- any store failure is unreachable
        cur = _UNREACHABLE
    if cur is _UNREACHABLE:
        checked.append("mandate:unreachable")
        return _deny("ptgrant-mandate-unreachable",
                     "mandate store unreachable", checked)
    if cur != body["mandate_version"]:
        checked.append("mandate:drift")
        return _deny("ptgrant-mandate-drift",
                     "mandate %r is at version %r, grant bound to %r"
                     % (body["mandate_id"], cur, body["mandate_version"]), checked)
    checked.append("mandate:ok")

    ident = "%s::%s" % (server_name, tool)
    detail = None
    for d in body["authorization_details"]:
        if d.get("identifier") == ident:
            detail = d
            break
    if detail is None:
        checked.append("detail:absent")
        return _deny("ptgrant-tool-not-covered",
                     "grant covers no tool %r" % (ident,), checked)
    if server_uri not in detail.get("locations", []):
        checked.append("detail:location-mismatch")
        return _deny("ptgrant-tool-not-covered",
                     "detail for %r not valid at %r" % (ident, server_uri), checked)
    checked.append("detail:ok")

    if not isinstance(args, dict):
        checked.append("args:malformed")
        return _deny("ptgrant-grant-malformed", "args must be an object", checked)

    # v2 (wave-271, opt-in): request-scoped invocation material (OpenFGA
    # contextual-tuples analog). Merged into the evaluation view for this
    # one check only -- never persisted. Caller-influenced, so it is
    # type-checked and size-capped like any untrusted input.
    ctx = None
    if request_context is not None:
        if not isinstance(request_context, dict):
            checked.append("context:malformed")
            return _deny("ptgrant-grant-malformed",
                         "request_context must be an object", checked)
        if len(_canonical(request_context)) > max_context_bytes:
            checked.append("context:oversize")
            return _deny("ptgrant-context-oversize",
                         "request_context exceeds %d bytes"
                         % (max_context_bytes,), checked)
        ctx = request_context
        checked.append("context:ok")

    missing = []
    for arg, bound in detail.get("arg_bounds", {}).items():
        pred = bound.get("predicate")
        if pred not in PREDICATE_REGISTRY:
            checked.append("arg:%s:unknown-predicate" % (arg,))
            return _deny("ptgrant-predicate-unknown",
                         "arg_bounds[%r] uses unknown predicate %r" % (arg, pred),
                         checked)
        val = args.get(arg, _MISSING)
        if val is _MISSING and ctx is not None:
            val = ctx.get(arg, _MISSING)
        if val is _MISSING:
            if ctx is not None:
                # v2: the attribute cannot be evaluated from stored params
                # or request-scoped material -> deny with the missing
                # fields logged (never a conditional permission).
                missing.append(arg)
                continue
            # v1 legacy path: missing arg evaluates the predicate against
            # None, which fails -> ptgrant-arg-bound-violated. Preserved
            # byte-for-byte when request_context is unset.
            val = None
        if not eval_predicate(pred, val, bound.get("params")):
            checked.append("arg:%s:violated" % (arg,))
            return _deny("ptgrant-arg-bound-violated",
                         "argument %r violates its bound" % (arg,), checked)
    if missing:
        checked.append("args:missing")
        return _deny("ptgrant-arg-attribute-missing",
                     "required argument attribute(s) missing: %s"
                     % (", ".join(sorted(missing)),), checked)
    checked.append("args:ok")

    aok, acode, adetail, budget = _check_attenuation(grant, holder_pub)
    checked.append("attenuation:%s" % acode)
    if not aok:
        return _deny(acode, adetail, checked)
    for rec in budget["caveats"]:
        pred, params = rec["predicate"], rec["params"]
        if pred == "arg_bound":
            arg = params.get("arg")
            # F287: caveats use the same args-then-request_context view
            # as grant-level arg_bounds -- attenuated grants work with
            # request-scoped attributes instead of falsely denying.
            val = args.get(arg, _MISSING)
            if val is _MISSING and ctx is not None:
                val = ctx.get(arg, _MISSING)
            if val is _MISSING:
                val = None  # legacy: predicate against None fails -> deny
            if not eval_predicate(params.get("predicate"), val,
                                  params.get("params")):
                checked.append("caveat:arg_bound:violated")
                return _deny("ptgrant-arg-bound-violated",
                             "attenuation caveat narrows arg %r beyond the call"
                             % (arg,), checked)
        else:
            # Caveats that only widen the check surface are meaningless;
            # a recognized predicate with params we do not apply is a
            # verifier-discipline failure -> deny (never silently skip).
            checked.append("caveat:%s:unevaluated" % (pred,))
            return _deny("ptgrant-attenuation-invalid",
                         "caveat predicate %r not applied at enforcement" % (pred,),
                         checked)
    checked.append("caveats:ok")

    effective_exp = body["exp"]
    if budget["exp"] is not None:
        if budget["exp"] > body["exp"]:
            checked.append("caveat:exp:widening")
            return _deny("ptgrant-attenuation-invalid",
                         "caveat exp exceeds grant exp", checked)
        effective_exp = budget["exp"]
    if now >= effective_exp:
        checked.append("caveat:exp:expired")
        return _deny("ptgrant-grant-expired",
                     "attenuation-shortened window elapsed", checked)

    try:
        link = link_verifier(tool)
    except Exception:  # noqa: BLE001
        link = None
    if not isinstance(link, str):
        checked.append("link:unverifiable")
        return _deny("ptgrant-link-unverifiable",
                     "supply-chain link for %r unverifiable" % (tool,), checked)
    if link != detail.get("supply_chain", {}).get("link_digest"):
        checked.append("link:mismatch")
        return _deny("ptgrant-supply-chain-failed",
                     "supply-chain link digest mismatch for %r" % (tool,), checked)
    checked.append("link:ok")

    max_calls = detail.get("max_calls")
    if budget["max_calls"] is not None:
        if budget["max_calls"] > max_calls:
            checked.append("caveat:max_calls:widening")
            return _deny("ptgrant-attenuation-invalid",
                         "caveat max_calls exceeds grant", checked)
        max_calls = budget["max_calls"]
    # F253: the nonce replay check runs BEFORE usage consumption. A proof
    # refused as ptgrant-jti-reused is budget-neutral -- a captured proof
    # replayed N times cannot drain the victim grant's max_calls.
    nonce = proof.get("nonce") if isinstance(proof, dict) else None
    if isinstance(nonce, str) and usage_store.seen_nonce(body["jti"], nonce):
        checked.append("proof:replayed")
        return _deny("ptgrant-jti-reused",
                     "proof nonce already presented for this grant", checked)
    checked.append("proof:fresh")

    consumed, remaining = usage_store.consume(body["jti"], max_calls)
    if not consumed:
        checked.append("budget:exhausted")
        return _deny("ptgrant-max-calls-exhausted",
                     "call budget exhausted for grant %r" % (body["jti"],), checked)
    checked.append("budget:ok")

    return {"ok": True, "code": "ptgrant-ok",
            "detail": "grant authorizes %r with %d call(s) remaining" % (ident, remaining),
            "checked": checked, "grant_jti": body["jti"],
            "remaining": remaining}


def grant_status(grant, *, issuer_pub, now, usage_store):
    """Introspection hook (secondary revocation path): live grant state."""
    ok, code, body = verify_grant(grant, issuer_pub=issuer_pub, now=now)
    if not ok:
        return {"active": False, "code": code}
    max_calls = max((d.get("max_calls", 0)
                     for d in body["authorization_details"]), default=0)
    st = usage_store.status(body["jti"], max_calls)
    return {"active": not st["exhausted"], "code": code, "jti": body["jti"],
            "exp": body["exp"], "calls_used": st["calls_used"],
            "calls_max": st["calls_max"]}


# ---------------------------------------------------------------------------
# Composition: authorization_combine external-authorizer provider
# ---------------------------------------------------------------------------

def make_ptgrant_provider(*, issuer_pub, server_name, server_uri, now_fn,
                          usage_store, mandate_version_provider, link_verifier,
                          decoy_registry=_DECOY_DEFAULT):
    """Return a ``(pid, request) -> (allowed, reason)`` CUSTOM provider.

    The request contract: ``request`` is a dict with ``grant`` (the PTG),
    ``proof`` (fresh per-call PoP proof), ``tool`` and ``args``. A provider
    deny decides immediately; a provider allow continues to the ALLOW
    bucket (it is not itself a grant) -- see authorization_combine.

    ``decoy_registry`` follows the enforce() default discipline (omitted
    -> default registry; None -> disabled).
    """

    def _provider(pid, request):
        try:
            verdict = enforce(
                request["grant"], proof=request["proof"], issuer_pub=issuer_pub,
                server_name=server_name, server_uri=server_uri,
                tool=request["tool"], args=request["args"], now=now_fn(),
                usage_store=usage_store,
                mandate_version_provider=mandate_version_provider,
                link_verifier=link_verifier,
                decoy_registry=decoy_registry)
        except Exception as exc:  # noqa: BLE001 -- provider never raises
            return False, "ptgrant provider error: %r" % (exc,)
        if verdict["ok"]:
            return True, "ptgrant-ok jti=%s" % (verdict["grant_jti"],)
        return False, "%s: %s" % (verdict["code"], verdict["detail"])

    return _provider


# ---------------------------------------------------------------------------
# v2 gateway evaluation (wave-271): production PDP disciplines
# ---------------------------------------------------------------------------
# Pattern sources (nothing copied): OpenFGA's dogfooded gateway (method ->
# relation mapping, in-process, request-scoped contextual tuples) and
# SpiceDB's zedtokens ((datastore, revision, schema-hash) pinning).
#
# The 7 falsifiable properties:
#  P1 stale mandate_version -> deny (zedtoken discipline)
#  P2 predicate-registry content-hash mismatch -> deny
#  P3 missing required arg_bounds attribute -> deny + missing fields logged
#  P4 request-scoped grant material never persists
#  P5 mandate store unreachable -> deny (fail closed, never noop-allow)
#  P6 batch verdicts: one per tool call, pinned snapshot, never shared
#  P7 admin/data-plane credential separation

_UNREACHABLE = object()


def evaluate_request(grant, *, proof, issuer_pub, server_name, server_uri,
                     tool, args, request_context, caller_cred, now,
                     usage_store, mandate_version_provider, link_verifier,
                     max_context_bytes=4096, verdict_cache=None,
                     decoy_registry=_DECOY_DEFAULT):
    """v2 gateway single-call evaluation. Never raises; fail-closed verdicts.

    Gateway meta-check order:
      caller scope (data-plane) -> mandate store reachability ->
      full enforce() with check_registry_pin=True and the request context.

    ``decoy_registry`` follows the enforce() default discipline (omitted
    -> default registry, canary on; None -> disabled).

    The mandate version is fetched ONCE per call; the pinned value is what
    enforce() re-checks, so a mandate bump landing mid-call cannot serve a
    stale allow within that call.

    ``verdict_cache`` (optional dict) caches DENIES only, keyed on
    (grant digest, server, tool, args digest, mandate version, registry
    hash, caller scope set, proof digest, request-context digest). Deny
    caching is sound because the key binds every input that participates
    in the verdict: an identical input replays an identical deny
    (F278 -- a deny cached for one proof/context is never served to a
    different proof/context). Allows are never cached, so no stale allow
    can be served.

    ``request_context`` is request-scoped invocation material merged into
    the evaluation view for this one check only; it is never persisted.
    A ``None`` context becomes an *empty* evaluation view, so a missing
    required attribute is always reported as
    ``ptgrant-arg-attribute-missing`` at the v2 gateway (never the v1
    ``ptgrant-arg-bound-violated``).
    """
    checked = []

    # P7: caller authentication at the gateway is a scoped-credential check
    # (OpenFGA lesson: the backend must not serve admin-key bearer tokens).
    scopes = (caller_cred.get("scopes") if isinstance(caller_cred, dict)
              else None)
    if not isinstance(scopes, list) or "data-plane" not in scopes:
        return _deny("ptgrant-caller-unauthorized",
                     "caller credential lacks the data-plane scope", checked)
    checked.append("caller:ok")

    # P5: reachability BEFORE any real evaluation (OpenFGA trap #3:
    # opt-in authz degrades to allow when the backend is gone; Sasanam
    # fails closed). A raising provider and a None-returning provider are
    # both "store unreachable".
    body = grant.get("body") if isinstance(grant, dict) else None
    mandate_id = body.get("mandate_id") if isinstance(body, dict) else None
    try:
        cur = mandate_version_provider(mandate_id)
    except Exception:  # noqa: BLE001 -- any store failure is unreachable
        cur = _UNREACHABLE
    if cur is _UNREACHABLE or cur is None:
        checked.append("mandate:unreachable")
        return _deny("ptgrant-mandate-unreachable",
                     "mandate store unreachable or mandate unknown", checked)
    checked.append("mandate:reachable")

    # P1/P2/P6: pinned snapshot -- every check in this call sees the same
    # mandate version and the live registry hash.
    def _pinned_provider(_mid, _cur=cur):
        return _cur

    # F278: the deny-cache key binds every input that participates in
    # the verdict -- grant, PROOF (identity), args, request_context,
    # mandate version, registry hash, caller scopes, and the decoy
    # registry (a deny cached without the canary is never served to a
    # call with the canary on, and vice versa). A deny cached for
    # one proof/context is never served to a different proof/context.
    ctx_view = request_context if request_context is not None else {}
    decoy_key = _resolve_decoy_registry(decoy_registry)
    decoy_key = None if decoy_key is None else decoy_key.names
    cache_key = None
    if verdict_cache is not None:
        try:
            gdigest = hashlib.sha256(_canonical(body)).hexdigest()
            adigest = hashlib.sha256(_canonical(args)).hexdigest()
            pdigest = (hashlib.sha256(_canonical(proof)).hexdigest()
                       if proof is not None else "no-proof")
            cdigest = hashlib.sha256(_canonical(ctx_view)).hexdigest()
            cache_key = (gdigest, server_name, tool, adigest, cur,
                         predicate_registry_hash(),
                         tuple(sorted(s for s in scopes
                                      if isinstance(s, str))),
                         pdigest, cdigest, decoy_key)
        except Exception:  # noqa: BLE001 -- unserializable shapes skip caching
            cache_key = None
        if cache_key is not None:
            hit = verdict_cache.get(cache_key)
            if (isinstance(hit, dict) and hit.get("ok") is False):
                checked.append("cache:deny-hit")
                out = dict(hit)
                out["checked"] = (list(hit.get("checked", []))
                                  + ["cache:deny-hit"])
                return out

    verdict = enforce(grant, proof=proof, issuer_pub=issuer_pub,
                      server_name=server_name, server_uri=server_uri,
                      tool=tool, args=args, now=now, usage_store=usage_store,
                      mandate_version_provider=_pinned_provider,
                      link_verifier=link_verifier,
                      request_context=ctx_view,
                      check_registry_pin=True,
                      max_context_bytes=max_context_bytes,
                      decoy_registry=decoy_registry)
    verdict["checked"] = checked + verdict.get("checked", [])
    if (verdict_cache is not None and cache_key is not None
            and verdict.get("ok") is False):
        verdict_cache[cache_key] = dict(verdict)
    return verdict


def evaluate_batch(items, *, grant, issuer_pub, server_name, server_uri,
                   now, usage_store, mandate_version_provider,
                   link_verifier, caller_cred, max_tools_per_request=8,
                   max_context_bytes=4096, verdict_cache=None,
                   decoy_registry=_DECOY_DEFAULT):
    """Evaluate a batch of tool calls. Returns
    ``{"snapshot": {...} or None, "verdicts": [verdict, ...]}``.

    P6: the mandate snapshot (mandate id/version + registry hash) is pinned
    ONCE for the whole batch; every item gets an INDEPENDENT verdict --
    decisions are never shared across tool calls, and a partial-coverage
    batch denies exactly the uncovered items. A batch larger than
    ``max_tools_per_request`` is denied item-by-item with
    ``ptgrant-batch-tool-cap-exceeded`` (a single denial record per item,
    so the response shape stays one-verdict-per-call).
    """
    if not isinstance(items, list) or not items:
        return {"snapshot": None, "verdicts": []}
    if len(items) > max_tools_per_request:
        v = {"ok": False, "code": "ptgrant-batch-tool-cap-exceeded",
             "detail": "batch of %d exceeds per-request cap %d"
                      % (len(items), max_tools_per_request),
             "checked": ["batch:cap-exceeded"], "grant_jti": None}
        return {"snapshot": None, "verdicts": [dict(v) for _ in items]}

    body = grant.get("body") if isinstance(grant, dict) else None
    mandate_id = body.get("mandate_id") if isinstance(body, dict) else None
    try:
        cur = mandate_version_provider(mandate_id)
    except Exception:  # noqa: BLE001
        cur = None
    snapshot = {"mandate_id": mandate_id, "mandate_version": cur,
                "predicate_registry_hash": predicate_registry_hash()}
    if cur is None:
        v = _deny("ptgrant-mandate-unreachable",
                  "mandate store unreachable", ["batch:mandate-unreachable"])
        return {"snapshot": snapshot,
                "verdicts": [dict(v) for _ in items]}

    def _pinned_provider(_mid, _cur=cur):
        return _cur

    verdicts = []
    for it in items:
        it = it if isinstance(it, dict) else {}
        verdicts.append(evaluate_request(
            grant, proof=it.get("proof"), issuer_pub=issuer_pub,
            server_name=server_name, server_uri=server_uri,
            tool=it.get("tool"), args=it.get("args"),
            request_context=it.get("request_context"),
            caller_cred=caller_cred, now=now, usage_store=usage_store,
            mandate_version_provider=_pinned_provider,
            link_verifier=link_verifier,
            max_context_bytes=max_context_bytes,
            verdict_cache=verdict_cache,
            decoy_registry=decoy_registry))
    return {"snapshot": snapshot, "verdicts": verdicts}


# ---------------------------------------------------------------------------
# Composition note: policy_delta
# ---------------------------------------------------------------------------
# PTG enforcement decisions compose with policy_delta as *deny-veto*
# inputs, never as allow overrides: a PTG refusal maps to a deny verdict
# in the policy engine, and a PTG grant never clears a policy deny or an
# Unknown (the wave-269 poldelta x exception composition). The join key is
# the (server_name, tool, canonical(args)) triple. This module does not
# fork policy_delta; the composition lives in the gateway.
#
# Honest limits of this module:
# - Single-process UsageStore default: one-shot semantics need a durable
#   backing in production (documented on the class).
# - The Tool AS is a module here (per prospectus OQ2: module first,
#   service boundary later); key custody follows gov/kms.py.
# - arg_bounds predicate vocabulary is v1 (prefix, one_of, max_len,
#   max_value, regex); new predicates need a registry version bump.
# - Nested ``act`` is never enforced; a deployment that needs
#   delegation-chain policy must consume it explicitly.
# - Exchange does not revoke the parent (RFC 8693 2.1).
# - The stale-revocation window equals the grant TTL when the
#   introspection secondary path is not consulted.
# - v2 (wave-271) honest limits:
#   - predicate_registry_hash() pins (version, name-set), not predicate
#     *implementations*: a same-version semantic change is caught only by
#     the deployment discipline of bumping PREDICATE_REGISTRY_VERSION.
#   - evaluate_request() refuses pre-v2 (unpinned) grants when
#     check_registry_pin=True: v1-issued grants must be re-issued to be
#     evaluated at the v2 gateway.
#   - verdict_cache caches denies only; a permit that turns into a deny
#     (tightened registry, consumed budget) is always re-evaluated.
#   - caller_cred is a gateway-supplied credential object; Sasanam does
#     not mint agent credentials (dex/federated identity is a separate
#     build lane).
#   - evaluate_batch() is a convenience over evaluate_request(): one
#     verdict per item, shared pinned snapshot, never shared decisions.
