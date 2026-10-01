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

from gov import ed25519

GRANT_TYPE = "https://sasanam.dev/mcp_tool_call"
GRANT_ISSUER = "sasanam-tool-as"
_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9_.\-]+::[A-Za-z0-9_.\-]+$")
_SPIFFE_RE = re.compile(r"^spiffe://[A-Za-z0-9_.\-/]+$")
_PROOF_SKEW_S = 60
_MAX_LIFETIME_S = 3600

# ---------------------------------------------------------------------------
# Decision codes (ptgrant domain; merged taxonomy pin 1372)
# ---------------------------------------------------------------------------

PTGRANT_CODES = [
    "ptgrant-arg-bound-violated",
    "ptgrant-attenuation-invalid",
    "ptgrant-audience-mismatch",
    "ptgrant-cnf-missing",
    "ptgrant-grant-expired",
    "ptgrant-grant-malformed",
    "ptgrant-grant-not-yet-valid",
    "ptgrant-invalid-target",
    "ptgrant-issuer-unknown",
    "ptgrant-jti-reused",
    "ptgrant-link-unverifiable",
    "ptgrant-mandate-drift",
    "ptgrant-max-calls-exhausted",
    "ptgrant-ok",
    "ptgrant-pop-invalid",
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
# Canonical bytes + small helpers
# ---------------------------------------------------------------------------

def _canonical(obj):
    """Deterministic JSON bytes for signing/digesting."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


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

    def __init__(self, iss, issuer_seed, mandate_lookup):
        if iss != GRANT_ISSUER:
            raise GrantError("ptgrant-issuer-unknown",
                             "issuer %r is not %r" % (iss, GRANT_ISSUER))
        if not isinstance(issuer_seed, (bytes, bytearray)) or len(issuer_seed) != 32:
            raise GrantError("ptgrant-grant-malformed", "issuer_seed must be 32 bytes")
        self._iss = iss
        self._seed = bytes(issuer_seed)
        self._pub = ed25519.publickey(self._seed)
        self._mandate_lookup = mandate_lookup

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
        }
        if act is not None:
            # Top-level claims only: nested ``act`` is informational and is
            # never consulted by enforcement (see enforce()).
            body["act"] = act
        body["jti"] = jti if isinstance(jti, str) and jti else \
            hashlib.sha256(_canonical(body)).hexdigest()[:32]
        sig = ed25519.sign(self._seed, _canonical(body))
        return {"body": body, "sig": _b64(sig), "attenuation": []}

    def exchange(self, parent, *, issuer_seed, details, now, proof_pub,
                 lifetime_s, act=None):
        """RFC 8693-style attenuation ceremony: mint a narrower child grant.

        The child must be within the parent's rights (identifiers present
        in the parent, bounds narrowed, max_calls not raised, lifetime
        within the parent's remaining window). Anything outside the parent
        refuses ``ptgrant-invalid-target``.

        TRAP (RFC 8693 2.1, carried honestly): exchanging does NOT revoke
        the parent. The parent remains valid until it expires.
        """
        pok, pcode, _ = verify_grant(parent, issuer_pub=self._pub, now=now)
        if not pok:
            raise GrantError(pcode, "parent grant is not valid for exchange")
        pbody = parent["body"]
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
    """Mint a per-call proof of possession bound to the grant's digest."""
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise GrantError("ptgrant-grant-malformed", "seed must be 32 bytes")
    seed = bytes(seed)
    body = grant["body"]
    digest = hashlib.sha256(_canonical(body)).hexdigest()
    proof = {
        "grant_digest": digest,
        "jti": body["jti"],
        "method": method,
        "uri": uri,
        "iat": now,
        "nonce": nonce if isinstance(nonce, str) and nonce else
        hashlib.sha256(_canonical([method, uri, now])).hexdigest()[:16],
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
            now, usage_store, mandate_version_provider, link_verifier):
    """Gateway enforcement, post-parse. Never raises; fail-closed verdicts.

    Check order: shape/signature -> issuer -> aud -> time -> PoP/cnf ->
    mandate version -> detail selection -> arg_bounds -> attenuation ->
    supply chain -> budget.
    """
    checked = []
    ok, code, _body = verify_grant(grant, issuer_pub=issuer_pub, now=now)
    checked.append("grant:%s" % code)
    if not ok:
        return _deny(code, "grant invalid", checked)
    body = _body

    if body["aud"] != server_uri or not isinstance(body["aud"], str):
        checked.append("aud:mismatch")
        return _deny("ptgrant-audience-mismatch",
                     "grant aud %r is not this server" % (body.get("aud"),), checked)
    checked.append("aud:ok")

    pok, pcode, pdetail, holder_pub = _check_proof(proof, grant, now)
    checked.append("pop:%s" % pcode)
    if not pok:
        return _deny(pcode, pdetail, checked)

    cur = mandate_version_provider(body["mandate_id"])
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
    for arg, bound in detail.get("arg_bounds", {}).items():
        pred = bound.get("predicate")
        if pred not in PREDICATE_REGISTRY:
            checked.append("arg:%s:unknown-predicate" % (arg,))
            return _deny("ptgrant-predicate-unknown",
                         "arg_bounds[%r] uses unknown predicate %r" % (arg, pred),
                         checked)
        if not eval_predicate(pred, args.get(arg), bound.get("params")):
            checked.append("arg:%s:violated" % (arg,))
            return _deny("ptgrant-arg-bound-violated",
                         "argument %r violates its bound" % (arg,), checked)
    checked.append("args:ok")

    aok, acode, adetail, budget = _check_attenuation(grant, holder_pub)
    checked.append("attenuation:%s" % acode)
    if not aok:
        return _deny(acode, adetail, checked)
    for rec in budget["caveats"]:
        pred, params = rec["predicate"], rec["params"]
        if pred == "arg_bound":
            arg = params.get("arg")
            if not eval_predicate(params.get("predicate"), args.get(arg),
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
    consumed, remaining = usage_store.consume(body["jti"], max_calls)
    if not consumed:
        checked.append("budget:exhausted")
        return _deny("ptgrant-max-calls-exhausted",
                     "call budget exhausted for grant %r" % (body["jti"],), checked)
    checked.append("budget:ok")

    nonce = proof.get("nonce") if isinstance(proof, dict) else None
    if isinstance(nonce, str) and usage_store.seen_nonce(body["jti"], nonce):
        checked.append("proof:replayed")
        return _deny("ptgrant-jti-reused",
                     "proof nonce already presented for this grant", checked)
    checked.append("proof:fresh")

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
                          usage_store, mandate_version_provider, link_verifier):
    """Return a ``(pid, request) -> (allowed, reason)`` CUSTOM provider.

    The request contract: ``request`` is a dict with ``grant`` (the PTG),
    ``proof`` (fresh per-call PoP proof), ``tool`` and ``args``. A provider
    deny decides immediately; a provider allow continues to the ALLOW
    bucket (it is not itself a grant) -- see authorization_combine.
    """

    def _provider(pid, request):
        try:
            verdict = enforce(
                request["grant"], proof=request["proof"], issuer_pub=issuer_pub,
                server_name=server_name, server_uri=server_uri,
                tool=request["tool"], args=request["args"], now=now_fn(),
                usage_store=usage_store,
                mandate_version_provider=mandate_version_provider,
                link_verifier=link_verifier)
        except Exception as exc:  # noqa: BLE001 -- provider never raises
            return False, "ptgrant provider error: %r" % (exc,)
        if verdict["ok"]:
            return True, "ptgrant-ok jti=%s" % (verdict["grant_jti"],)
        return False, "%s: %s" % (verdict["code"], verdict["detail"])

    return _provider


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
