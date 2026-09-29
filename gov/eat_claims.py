"""EAT-shaped attestation claims (RFC 9711, Entity Attestation Token).

ADAPT verdict from the wave-209 prospectus: map our attested-identity
evidence (TPM quote, TEE report, cloud IID) onto the EAT claim inventory
and emit it as JSON/JWT -- the RFC's normative JSON path -- in a
JOSE/Ed25519 (EdDSA) envelope. A written Sasanam EAT profile
(docs/eat-profile.md) pins every option RFC 9711 leaves open.

**EAT-shaped, not wire-interoperable.** CBOR/COSE emission is explicitly
SKIP for v1: stdlib has no CBOR, and no v1 consumer needs the CBOR wire.
The value is the claim-shape mapping plus the profile discipline, not
the wire code. Never claim EAT conformance or interoperability.

Design rules (adopted verbatim from RFC 9711):

* **No claim inheritance across submods.** Attester facts (ueid, oemid,
  hwmodel, measurements, dbgstat, ...) live ONLY inside the submodule
  that measured them. The superior claims set carries only the token
  frame (iss/iat/exp/cti), the superior freshness nonce, the pinned
  profile, and the declared intent. Each submod carries its OWN freshness
  nonce -- a submod may never ride the superior module's nonce, and the
  verifier requires an expected nonce per submod. This is enforced at
  emit time AND at verify time.
* **Unknown claims are tolerated, never errors** (RFC section 6.3
  posture): the verifier fails closed only on claims it *understands*
  that violate policy. The envelope header is the exception: it is
  closed to {alg, typ, kid} so the signature cannot be re-targeted.
* **Freshness is mandatory.** Every token and every submod binds a
  single-use nonce (eat_nonce), compared with hmac.compare_digest.
* **Narrow claims.** Emitting an EAT standardizes the *vocabulary* of
  the claim, never its strength. `eat_claim_bounds()` returns a
  claim-bounds record (valid under gov/claim_bounds.py) stating what an
  emitted token proves and what it explicitly does not: attester
  strength, workload behavior, and ongoing validity beyond `exp` are
  disavowed. A token whose measurements do not match the verifier's
  reference values is refused.

stdlib only. $0 spend. No network.
"""

import base64
import hashlib
import hmac
import json
import secrets
import time

from . import ed25519 as _ed25519
from .attested_identity import canonical_json as _canonical_json


class EATError(Exception):
    """Base class for EAT-shaped claim errors."""


class EATBuildError(EATError):
    """Emission-time refusal: malformed evidence or closed-set violation."""


class EATVerifyError(EATError):
    """Verification-time refusal: signature, freshness, policy, or bounds."""


# -- profile pinning --------------------------------------------------------

#: The one and only profile this module emits and verifies. The verifier
#: refuses any token whose eat_profile differs: profile confusion is a
#: token-confusion attack. See docs/eat-profile.md.
EAT_PROFILE_V1 = "https://sasanam.dev/profiles/attested-identity/v1"

#: Declared intent of every emitted token (intuse claim, CWT key 275).
EAT_INTUSE = "workload-bound key issuance for agent identity"

#: JWS envelope pinned by the profile. EdDSA = pure Ed25519 over the
#: ASCII signing input (RFC 8037); typ pins the EAT JWT media type.
_JWS_ALG = "EdDSA"
_JWS_TYP = "application/eat+jwt"

#: Closed composition: which attesters may appear as submods. An unknown
#: submod name is refused at emit time, never silently mapped.
SUPPORTED_SUBMODS = ("tpm", "tee", "aws_iid", "gcp_iid")

#: Attester facts that must never appear in the superior claims set.
#: This set is the code form of the no-inheritance rule.
_SUBMOD_ONLY_CLAIMS = frozenset((
    "ueid", "sueids", "oemid", "hwmodel", "hwversion", "uptime",
    "bootcount", "bootseed", "dbgstat", "location", "swname",
    "swversion", "manifests", "measurements", "measres",
))

#: EAT claim name -> CWT key number (RFC 9711, section 5 CDDL). The
#: JSON names are emitted; the numbers are documented so a future
#: CBOR/CWT lane has the mapping pinned here, not re-derived.
EAT_CLAIM_KEYS = {
    "iss": 1, "sub": 2, "aud": 3, "exp": 4, "nbf": 5, "iat": 6,
    "cti": 7,
    "eat_nonce": 10,
    "ueid": 256, "sueids": 257, "oemid": 257, "hwmodel": 258,
    "hwversion": 260, "uptime": 261, "bootcount": 267, "bootseed": 268,
    "dbgstat": 263, "location": 264, "eat_profile": 265, "submods": 266,
    "swname": 270, "swversion": 271, "manifests": 272,
    "measurements": 273, "measres": 274, "intuse": 275,
}

_MEASRES_PASS = "pass"
_MEASRES_FAIL = "fail"
_MEASRES_UNASSESSED = "unassessed"

# -- base64url ---------------------------------------------------------------


def _b64u(raw):
    """base64url-encode bytes, no padding (JOSE compact serialization)."""
    if not isinstance(raw, (bytes, bytearray)) or not raw:
        raise EATBuildError("_b64u needs non-empty bytes")
    return base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")


def _b64u_decode(text, what):
    """Strict base64url decode; raises EATVerifyError on hostile input."""
    if not isinstance(text, str) or not text:
        raise EATVerifyError("%s must be a non-empty str" % what)
    if any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789-_"
           for c in text):
        raise EATVerifyError("%s is not base64url" % what)
    padded = text + "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        raise EATVerifyError("%s is not decodable base64url" % what)


# -- emission ----------------------------------------------------------------


def _check_evidence(evidence):
    if not isinstance(evidence, dict) or not evidence:
        raise EATBuildError("evidence must be a non-empty dict of submods")
    for name, rec in evidence.items():
        if name not in SUPPORTED_SUBMODS:
            raise EATBuildError(
                "unknown submod %r: composition is closed to %s"
                % (name, ", ".join(SUPPORTED_SUBMODS)))
        if not isinstance(rec, dict):
            raise EATBuildError("submod %r evidence must be a dict" % name)
        for field in ("ueid", "dbgstat", "nonce", "measurements"):
            if field not in rec:
                raise EATBuildError(
                    "submod %r is missing required field %r" % (name, field))
        if not isinstance(rec["ueid"], str) or not rec["ueid"]:
            raise EATBuildError("submod %r ueid must be a non-empty str"
                                % name)
        if rec["dbgstat"] not in ("disabled", "enabled"):
            raise EATBuildError(
                "submod %r dbgstat must be 'disabled' or 'enabled'" % name)
        if not isinstance(rec["nonce"], (bytes, bytearray)) \
                or not rec["nonce"]:
            raise EATBuildError(
                "submod %r nonce must be non-empty bytes (freshness is "
                "mandatory; a submod may never ride the superior nonce)"
                % name)
        if not isinstance(rec["measurements"], dict) \
                or not rec["measurements"]:
            raise EATBuildError(
                "submod %r measurements must be a non-empty dict" % name)
        for mname, mval in rec["measurements"].items():
            if not isinstance(mname, str) or not mname:
                raise EATBuildError(
                    "submod %r has a non-string measurement name" % name)
            if not isinstance(mval, str) or not mval:
                raise EATBuildError(
                    "submod %r measurement %r must be a non-empty str"
                    % (name, mname))
        for opt in ("oemid", "hwmodel", "hwversion", "swname",
                    "swversion", "manifest_digest"):
            if opt in rec and (not isinstance(rec[opt], str)
                               or not rec[opt]):
                raise EATBuildError(
                    "submod %r optional field %r must be a non-empty str"
                    % (name, opt))


def _submod_claims(name, rec, expectations):
    claims = {
        "ueid": rec["ueid"],
        "dbgstat": rec["dbgstat"],
        "eat_nonce": _b64u(bytes(rec["nonce"])),
        "measurements": dict(rec["measurements"]),
    }
    for opt, claim in (("oemid", "oemid"), ("hwmodel", "hwmodel"),
                       ("hwversion", "hwversion"), ("swname", "swname"),
                       ("swversion", "swversion"),
                       ("manifest_digest", "manifests")):
        if opt in rec:
            claims[claim] = rec[opt]
    ref = (expectations or {}).get(name, {})
    verdicts = []
    for mname in rec["measurements"]:
        if mname in ref:
            verdicts.append(_MEASRES_PASS
                            if hmac.compare_digest(rec["measurements"][mname],
                                                   ref[mname])
                            else _MEASRES_FAIL)
    if _MEASRES_FAIL in verdicts:
        claims["measres"] = _MEASRES_FAIL
    elif verdicts:
        claims["measres"] = _MEASRES_PASS
    else:
        # No reference values for this submod: the token honestly says
        # so instead of asserting an unevidenced pass.
        claims["measres"] = _MEASRES_UNASSESSED
    return claims


def _sign_claims(claims, signer):
    """Sign a claims dict as compact JWS. Test seam: lets probes re-sign
    modified claims to isolate verifier behavior from emitter behavior."""
    if not callable(signer):
        raise EATBuildError("signer must be callable")
    header = {"alg": _JWS_ALG, "typ": _JWS_TYP}
    try:
        signing_input = (_b64u(_canonical_json(header)) + "."
                         + _b64u(_canonical_json(claims))).encode("ascii")
    except Exception as e:
        raise EATBuildError("claims are not canonical-JSON serializable: %s"
                            % (e,))
    sig = signer(signing_input)
    if not isinstance(sig, (bytes, bytearray)) or len(sig) != 64:
        raise EATBuildError("signer must return a 64-byte Ed25519 signature")
    return signing_input.decode("ascii") + "." + _b64u(bytes(sig))


def emit_eat(*, evidence, nonce, issuer, signer, now=None, ttl_s=300,
             cti=None, expectations=None):
    """Emit an EAT-shaped token (compact JWS) from attested evidence.

    `evidence` maps submod name -> evidence record; see `_check_evidence`.
    `nonce` is the superior freshness nonce (bytes); each submod carries
    its own. `expectations` maps submod -> {measurement: reference value}
    and drives the per-submod `measres` verdict.
    """
    _check_evidence(evidence)
    if not isinstance(nonce, (bytes, bytearray)) or not nonce:
        raise EATBuildError("nonce must be non-empty bytes")
    if not isinstance(issuer, str) or not issuer:
        raise EATBuildError("issuer must be a non-empty str")
    if not isinstance(ttl_s, int) or isinstance(ttl_s, bool) or ttl_s <= 0:
        raise EATBuildError("ttl_s must be a positive int")
    now = int(now) if now is not None else int(time.time())
    if cti is None:
        cti = _b64u(secrets.token_bytes(16))
    if not isinstance(cti, str) or not cti:
        raise EATBuildError("cti must be a non-empty str")
    if expectations is not None and not isinstance(expectations, dict):
        raise EATBuildError("expectations must be a dict or None")

    claims = {
        "iss": issuer,
        "iat": now,
        "exp": now + ttl_s,
        "cti": cti,
        "eat_nonce": _b64u(bytes(nonce)),
        "eat_profile": EAT_PROFILE_V1,
        "intuse": EAT_INTUSE,
        "submods": {},
    }
    # No-inheritance, emit side: attester facts are built only inside
    # submods, never copied to the superior claims set.
    for name, rec in evidence.items():
        claims["submods"][name] = _submod_claims(name, rec, expectations)
    leaked = _SUBMOD_ONLY_CLAIMS & set(claims)
    if leaked:
        raise EATBuildError(
            "no-inheritance violation at emit: %s in superior claims"
            % sorted(leaked))
    return _sign_claims(claims, signer)


# -- verification ------------------------------------------------------------


def _check_header(header):
    if not isinstance(header, dict):
        raise EATVerifyError("JWS header must be a JSON object")
    allowed = {"alg", "typ", "kid"}
    unknown = set(header) - allowed
    if unknown:
        raise EATVerifyError(
            "JWS header has unknown fields %s: the envelope is closed"
            % sorted(unknown))
    if header.get("alg") != _JWS_ALG:
        raise EATVerifyError(
            "JWS alg must be %r (algorithm confusion refused)" % _JWS_ALG)
    if header.get("typ") != _JWS_TYP:
        raise EATVerifyError(
            "JWS typ must be %r (token-type confusion refused)" % _JWS_TYP)


def verify_eat(token, *, issuer_pubkey, expected_issuer, expected_nonce,
               expected_submod_nonces, expectations=None, now=None,
               allow_unassessed=False):
    """Verify an EAT-shaped token. Returns {"claims":..., "header":...}.

    Raises EATVerifyError on any refusal. Unknown *payload* claims are
    tolerated (RFC 6.3 posture); known claims violating policy fail
    closed. The envelope header is closed; the profile is pinned.
    """
    if not isinstance(token, str) or token.count(".") != 2:
        raise EATVerifyError("token must be a compact JWS string")
    if not isinstance(issuer_pubkey, (bytes, bytearray)) \
            or len(issuer_pubkey) != 32:
        raise EATVerifyError("issuer_pubkey must be a 32-byte Ed25519 key")
    if not isinstance(expected_issuer, str) or not expected_issuer:
        raise EATVerifyError("expected_issuer must be a non-empty str")
    if not isinstance(expected_nonce, (bytes, bytearray)) \
            or not expected_nonce:
        raise EATVerifyError("expected_nonce must be non-empty bytes")
    if not isinstance(expected_submod_nonces, dict) \
            or not expected_submod_nonces:
        raise EATVerifyError(
            "expected_submod_nonces must be a non-empty dict: freshness "
            "does not inherit from the superior module")
    now = int(now) if now is not None else int(time.time())
    if expectations is not None and not isinstance(expectations, dict):
        raise EATVerifyError("expectations must be a dict or None")

    h_b64, p_b64, s_b64 = token.split(".")
    try:
        header = json.loads(_b64u_decode(h_b64, "header").decode("ascii"))
    except EATVerifyError:
        raise
    except Exception:
        raise EATVerifyError("JWS header is not JSON")
    _check_header(header)
    try:
        claims = json.loads(_b64u_decode(p_b64, "payload").decode("ascii"))
    except EATVerifyError:
        raise
    except Exception:
        raise EATVerifyError("JWS payload is not JSON")
    if not isinstance(claims, dict):
        raise EATVerifyError("JWS payload must be a JSON object")
    sig = _b64u_decode(s_b64, "signature")
    if len(sig) != 64:
        raise EATVerifyError("signature must be 64 bytes")
    signing_input = (h_b64 + "." + p_b64).encode("ascii")
    try:
        ok = _ed25519.verify(bytes(issuer_pubkey), signing_input, bytes(sig))
    except Exception:
        ok = False
    if not ok:
        raise EATVerifyError("Ed25519 signature verification failed")

    # -- superior claims -------------------------------------------------
    if claims.get("eat_profile") != EAT_PROFILE_V1:
        raise EATVerifyError(
            "eat_profile %r is not the pinned profile %r: profile "
            "confusion refused" % (claims.get("eat_profile"),
                                   EAT_PROFILE_V1))
    if claims.get("iss") != expected_issuer:
        raise EATVerifyError("iss does not match the expected issuer")
    try:
        token_nonce = _b64u_decode(claims.get("eat_nonce"), "eat_nonce")
    except EATVerifyError as e:
        raise EATVerifyError("eat_nonce invalid: %s" % (e,))
    if not hmac.compare_digest(bytes(token_nonce), bytes(expected_nonce)):
        raise EATVerifyError("eat_nonce does not match: replay or "
                             "misdirected token refused")
    iat = claims.get("iat")
    exp = claims.get("exp")
    if not isinstance(iat, int) or isinstance(iat, bool) \
            or not isinstance(exp, int) or isinstance(exp, bool):
        raise EATVerifyError("iat/exp must be ints")
    if not (iat <= now < exp):
        raise EATVerifyError("token is not live (iat/exp window)")
    if not isinstance(claims.get("cti"), str) or not claims["cti"]:
        raise EATVerifyError("cti must be a non-empty str")
    leaked = _SUBMOD_ONLY_CLAIMS & set(claims)
    if leaked:
        raise EATVerifyError(
            "no-claim-inheritance violation: attester facts %s appear in "
            "the superior claims set" % sorted(leaked))

    # -- submods ----------------------------------------------------------
    submods = claims.get("submods")
    if not isinstance(submods, dict) or not submods:
        raise EATVerifyError("submods must be a non-empty object")
    for name in submods:
        if name not in SUPPORTED_SUBMODS:
            raise EATVerifyError(
                "unknown submod %r: composition is closed" % (name,))
    for name in (expectations or {}):
        if name not in submods:
            raise EATVerifyError(
                "verifier expects submod %r but the token has none" % name)
    for name, sub in submods.items():
        if not isinstance(sub, dict):
            raise EATVerifyError("submod %r must be an object" % name)
        if name not in expected_submod_nonces:
            raise EATVerifyError(
                "no expected nonce for submod %r: freshness does not "
                "inherit from the superior module" % name)
        try:
            sub_nonce = _b64u_decode(sub.get("eat_nonce"),
                                     "submod %r eat_nonce" % name)
        except EATVerifyError as e:
            raise EATVerifyError(str(e))
        if not hmac.compare_digest(bytes(sub_nonce),
                                   bytes(expected_submod_nonces[name])):
            raise EATVerifyError(
                "submod %r freshness mismatch: stale or foreign submod "
                "refused" % name)
        if not isinstance(sub.get("ueid"), str) or not sub["ueid"]:
            raise EATVerifyError("submod %r ueid must be a non-empty str"
                                 % name)
        if sub.get("dbgstat") != "disabled":
            raise EATVerifyError(
                "submod %r dbgstat is %r: debug-enabled attestation is "
                "refused fail-closed" % (name, sub.get("dbgstat")))
        measurements = sub.get("measurements")
        if not isinstance(measurements, dict) or not measurements:
            raise EATVerifyError(
                "submod %r measurements must be a non-empty object" % name)
        measres = sub.get("measres")
        if measres == _MEASRES_FAIL:
            raise EATVerifyError(
                "submod %r measres is fail: measurements do not match "
                "reference values" % name)
        if measres == _MEASRES_UNASSESSED and not allow_unassessed:
            raise EATVerifyError(
                "submod %r measres is unassessed: no reference values; "
                "refused unless allow_unassessed" % name)
        if measres not in (_MEASRES_PASS, _MEASRES_FAIL,
                           _MEASRES_UNASSESSED):
            raise EATVerifyError(
                "submod %r has an unknown measres value" % name)
        ref = (expectations or {}).get(name, {})
        for mname, mval in measurements.items():
            if mname in ref and not hmac.compare_digest(str(mval),
                                                        str(ref[mname])):
                raise EATVerifyError(
                    "submod %r measurement %r does not match the reference "
                    "value" % (name, mname))
        # Unknown submod claims are tolerated per RFC 6.3; only known
        # claims are enforced above.
    return {"claims": claims, "header": header}


# -- evidence / claim-bounds bridge ------------------------------------------


def eat_claim_bounds():
    """Claim bounds for an emitted EAT-shaped token, valid under
    gov/claim_bounds.py. This is the narrow-claims discipline as code:
    the token proves vocabulary-standardized measurements and freshness
    bindings; it explicitly does not prove attester strength, workload
    behavior, or anything beyond `exp`."""
    bounds = {
        "proves": [
            "eat-profile conformance of the claim set",
            "freshness binding of token and submods to single-use nonces",
            "measurement value equality against verifier reference values",
            "debug-disabled state at attestation time",
            "issuer key identity of the token signer",
        ],
        "does_not_prove": [
            "attester implementation strength",
            "workload behavior inside the attested environment",
            "validity beyond the token exp time",
            "truth of vendor-supplied oemid/hwmodel labels",
            "ongoing platform state after attestation time",
        ],
        "verifier_assumptions": [
            "issuer public key is pinned out-of-band in the trust config",
            "freshness nonces are delivered to the verifier out-of-band",
            "measurement reference values come from a trusted manifest",
        ],
        "scope_limits": [
            "JSON/JWT serialization only; no CBOR/COSE wire",
            "closed submod composition: tpm, tee, aws_iid, gcp_iid",
            "synthetic fixtures only: no live-hardware interop",
        ],
    }
    from . import claim_bounds as _cb
    _cb.validate_bounds(bounds)
    return bounds


def token_evidence_record(token, *, verified_claims):
    """Digest-identity record binding an EAT-shaped token to evidence.

    Returns {"token_sha256": hex, "profile": ..., "submods": [...],
    "measres": {name: verdict}} for claim-assignment / evidence-bundle
    consumers. `verified_claims` must be the claims dict from verify_eat.
    """
    if not isinstance(token, str) or not token:
        raise EATBuildError("token must be a non-empty str")
    if not isinstance(verified_claims, dict):
        raise EATBuildError("verified_claims must be the verified claims dict")
    submods = verified_claims.get("submods")
    if not isinstance(submods, dict):
        raise EATBuildError("verified_claims has no submods")
    return {
        "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "profile": verified_claims.get("eat_profile"),
        "submods": sorted(submods),
        "measres": {name: sub.get("measres")
                    for name, sub in sorted(submods.items())},
    }
