"""UCAN-style attenuation-only signed delegation chains (wave-265).

An ADAPT of the *delegation pattern* from storacha/ucanto
(dual-licensed MIT OR Apache-2.0 -- pattern only; no ucanto code or
spec text is read, copied, imported, or vendored):

* **Attenuation-only delegation.** A delegator issues a signed
  delegation granting a subset of the authority it holds. Every hop
  in a chain can only NARROW its parent's authority: issuing a
  delegation that widens the issuer's held scope is a structural
  refusal (``delegation-would-widen``) at issue time, and a
  widening hop inside a presented chain is refused at verification
  (``delegation-attenuation-inverted``). Attenuation is structural,
  never a runtime check to forget.
* **Chain of signed delegations.** Each delegation embeds the digest
  of its parent; the chain is verified hop by hop in a fixed order:
  type -> structure -> parent digest -> signature -> root trust ->
  attenuation -> time window -> action coverage -> replay. The root
  issuer must be pinned in the deployment's trust anchors.
* **Invocation receipts.** :meth:`DelegationVerifier.verify` mints a
  signed receipt per verified invocation, shaped for evidence
  bundles (same discipline as mandate receipts).
* **Capabilities are ``{with, can}`` pairs (UCAN-shaped).**
  ``with`` names the resource namespace (a prefix hierarchy:
  ``fs:/docs`` sits under ``fs:/``); ``can`` names the granted
  actions (``"*"`` is the only wildcard, covering any action).
  Attenuation: ``child.with`` must sit under ``parent.with`` and
  ``child.can`` must be a subset of ``parent.can``.

Wire format (documented so deployments can re-verify
cross-implementation): canonical JSON (``sort_keys=True``,
``separators=(",", ":")``, UTF-8); delegation digest is
``SHA-256(canonical_bytes(body))``. This is NOT a real CID -- we
deliberately do not implement IPLD/CID; the digest is only
CID-*compatible* in the hash-function choice (sha2-256 over the
canonical bytes), so a future CID-carrying implementation could
re-hash the same bytes and agree.

Signatures are Ed25519 (``gov.ed25519``; ``verify`` returns exact
True/False, checked with ``is True`` per the wave-243 lesson) over
domain-separated signing bytes (the w244 house standard):

* ``SIGN_DOMAIN``    -- delegation sealing
* ``RECEIPT_DOMAIN`` -- invocation receipts

Composition (never duplication):

* Identity: a delegation names issuer/audience *keys*, not
  principals. Audience binding (proving the presenter holds the
  audience key) is the deployment's authentication seam -- compose
  with ``gov/mesh_auth.py`` or ``gov/svid_issuer.py`` there.
* Mandates: an open mandate's tool allowlist / data scopes describe
  bounds; a delegation chain describes *who may act within bounds*.
  :meth:`DelegationVerifier.receipt` returns a signed receipt record
  ready to embed in an evidence bundle or decision packet.
* Decision codes are EVIDENCE, never authority.

Fail-closed throughout: malformed delegations, chains, keys, or
windows refuse before verification; unknown type versions refuse
before interpretation; an empty trust-anchor list refuses every
chain; replay state is in-memory per verifier instance (documented
residual -- deployments needing durable replay protection persist
the seen set or re-verify the full chain from the journal).

Honest residuals: the trust anchors and the verifier's receipt
signing seed are deployment-owned (no key ceremony here);
``audience`` is a recorded intent, not a proof of presentation;
replay/seen state is in-memory per verifier instance; the verifier
sees the action's ``{with, can}`` shape, never the action payload.
"""

import hashlib
import json
import secrets
import time

from . import ed25519

DELEGATION_TYPE = "delegation.ucan.1"
RECEIPT_TYPE = "delegation.receipt.1"

SIGN_DOMAIN = b"gov-delegation-sign/v1\x00"
RECEIPT_DOMAIN = b"gov-delegation-receipt/v1\x00"

_PUB_HEX_LEN = 64
_SIG_HEX_LEN = 128
_DIGEST_HEX_LEN = 64


class DelegationError(Exception):
    """Base for all delegation refusals; carries the machine code."""
    code = "delegation-malformed"


class DelegationMalformed(DelegationError):
    code = "delegation-malformed"


class DelegationVersionMismatch(DelegationError):
    code = "delegation-version-mismatch"


class DelegationSignatureInvalid(DelegationError):
    code = "delegation-signature-invalid"


class DelegationParentMismatch(DelegationError):
    code = "delegation-parent-mismatch"


class DelegationRootUntrusted(DelegationError):
    code = "delegation-root-untrusted"


class DelegationAttenuationInverted(DelegationError):
    code = "delegation-attenuation-inverted"


class DelegationActionRefused(DelegationError):
    code = "delegation-action-refused"


class DelegationReplay(DelegationError):
    code = "delegation-replay"


class DelegationExpired(DelegationError):
    code = "delegation-expired"


class DelegationWouldWiden(DelegationError):
    # Reuses the existing taxonomy code: the semantics are exactly
    # "the delegation would widen scope".
    code = "delegation-would-widen"


def _canonical(obj):
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def digest_of(body):
    """SHA-256 hex digest of the canonical delegation body bytes."""
    return hashlib.sha256(_canonical(body)).hexdigest()


def _is_hex(s, length):
    return isinstance(s, str) and len(s) == length and all(
        c in "0123456789abcdef" for c in s)


def _check_capability(cap):
    if not isinstance(cap, dict):
        raise DelegationMalformed(
            "capability must be a dict, got %s" % type(cap).__name__)
    with_ = cap.get("with")
    can = cap.get("can")
    if not isinstance(with_, str) or not with_:
        raise DelegationMalformed(
            "capability 'with' must be a non-empty string")
    if (not isinstance(can, list) or not can or
            any(not isinstance(a, str) or not a for a in can)):
        raise DelegationMalformed(
            "capability 'can' must be a non-empty list of strings")
    return {"with": with_, "can": list(can)}


def _check_capabilities(caps):
    if not isinstance(caps, list) or not caps:
        raise DelegationMalformed(
            "capabilities must be a non-empty list")
    return [_check_capability(c) for c in caps]


def _check_window(not_before, not_after):
    for name, value in (("not_before", not_before),
                        ("not_after", not_after)):
        if isinstance(value, bool) or \
                not isinstance(value, (int, float)):
            raise DelegationMalformed(
                "%s must be numeric, got %s"
                % (name, type(value).__name__))
    if not not_before < not_after:
        raise DelegationMalformed(
            "not_before must be strictly before not_after")


def _check_now(now):
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise DelegationMalformed(
            "now must be numeric, got %s" % type(now).__name__)
    return now


def _with_covered(child_with, parent_with):
    """True iff child_with names a resource under parent_with."""
    if child_with == parent_with:
        return True
    return child_with.startswith(parent_with.rstrip("/") + "/")


def _cap_covered(child, parent):
    if not _with_covered(child["with"], parent["with"]):
        return False
    if "*" in parent["can"]:
        return True
    return set(child["can"]) <= set(parent["can"])


def _caps_covered(child_caps, parent_caps):
    return all(any(_cap_covered(c, p) for p in parent_caps)
               for c in child_caps)


def _seal_body(body):
    """Validate the body shape; returns the normalized body."""
    if not isinstance(body, dict):
        raise DelegationMalformed("delegation body must be a dict")
    if body.get("type") != DELEGATION_TYPE:
        raise DelegationVersionMismatch(
            "unknown delegation type %r" % (body.get("type"),))
    issuer = body.get("issuer")
    audience = body.get("audience")
    if not _is_hex(issuer, _PUB_HEX_LEN):
        raise DelegationMalformed("issuer must be 64 hex chars")
    if not _is_hex(audience, _PUB_HEX_LEN):
        raise DelegationMalformed("audience must be 64 hex chars")
    capabilities = _check_capabilities(body.get("capabilities"))
    _check_window(body.get("not_before"), body.get("not_after"))
    parent_digest = body.get("parent_digest")
    if parent_digest is not None and \
            not _is_hex(parent_digest, _DIGEST_HEX_LEN):
        raise DelegationMalformed(
            "parent_digest must be null or 64 hex chars")
    nonce = body.get("nonce")
    if not isinstance(nonce, str) or not nonce:
        raise DelegationMalformed("nonce must be a non-empty string")
    return {
        "type": DELEGATION_TYPE,
        "issuer": issuer,
        "audience": audience,
        "capabilities": capabilities,
        "not_before": body["not_before"],
        "not_after": body["not_after"],
        "nonce": nonce,
        "parent_digest": parent_digest,
    }


def _check_sealed(sealed):
    if not isinstance(sealed, dict):
        raise DelegationMalformed("sealed delegation must be a dict")
    body = _seal_body(sealed.get("delegation"))
    sig = sealed.get("signature")
    if not _is_hex(sig, _SIG_HEX_LEN):
        raise DelegationSignatureInvalid(
            "signature must be 128 hex chars")
    return body, sig


def delegate(seed, held, request):
    """Issue (sign) a delegation.

    ``seed``: the issuer's 32-byte Ed25519 seed. ``held``: the
    capabilities the issuer holds (None for a root grant from the
    issuer's own authority). ``request``: dict with ``audience``
    (64-hex pubkey), ``capabilities``, ``not_before``/``not_after``,
    optional ``nonce``, and ``parent`` (a sealed parent delegation
    or None for a root).
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise DelegationMalformed("seed must be 32 bytes")
    if not isinstance(request, dict):
        raise DelegationMalformed("request must be a dict")
    capabilities = _check_capabilities(request.get("capabilities"))
    if held is not None:
        held_caps = _check_capabilities(held)
        if not _caps_covered(capabilities, held_caps):
            raise DelegationWouldWiden(
                "requested capabilities exceed the issuer's held "
                "scope; attenuation is narrowing-only")
    audience = request.get("audience")
    if not _is_hex(audience, _PUB_HEX_LEN):
        raise DelegationMalformed("audience must be 64 hex chars")
    _check_window(request.get("not_before"), request.get("not_after"))
    parent = request.get("parent")
    if parent is None:
        parent_digest = None
    else:
        parent_body, _ = _check_sealed(parent)
        parent_digest = digest_of(parent_body)
    nonce = request.get("nonce")
    if nonce is None:
        nonce = secrets.token_hex(16)
    if not isinstance(nonce, str) or not nonce:
        raise DelegationMalformed("nonce must be a non-empty string")
    issuer = ed25519.publickey(bytes(seed)).hex()
    body = {
        "type": DELEGATION_TYPE,
        "issuer": issuer,
        "audience": audience,
        "capabilities": capabilities,
        "not_before": request["not_before"],
        "not_after": request["not_after"],
        "nonce": nonce,
        "parent_digest": parent_digest,
    }
    sig = ed25519.sign(bytes(seed),
                       SIGN_DOMAIN + _canonical(body)).hex()
    return {"delegation": body, "signature": sig}


class DelegationVerifier(object):
    """Verify (chain, action) presentations against trust anchors.

    ``trust_anchors``: deployment-owned list of root issuer pubkeys
    (64-hex). An empty list refuses every chain. ``seed``: optional
    32-byte Ed25519 seed used to sign invocation receipts; when None
    the receipt carries ``signature: None`` (documented, not silent).
    """

    def __init__(self, trust_anchors, seed=None):
        if not isinstance(trust_anchors, (list, tuple)):
            raise DelegationMalformed(
                "trust_anchors must be a list of 64-hex pubkeys")
        for anchor in trust_anchors:
            if not _is_hex(anchor, _PUB_HEX_LEN):
                raise DelegationMalformed(
                    "trust anchor must be 64 hex chars")
        if seed is not None and \
                (not isinstance(seed, (bytes, bytearray)) or
                 len(seed) != 32):
            raise DelegationMalformed(
                "verifier seed must be 32 bytes or None")
        self._anchors = set(trust_anchors)
        self._seed = bytes(seed) if seed is not None else None
        self._seen = set()

    def _verify_signature(self, body, sig_hex):
        try:
            sig = bytes.fromhex(sig_hex)
            pub = bytes.fromhex(body["issuer"])
        except ValueError:
            raise DelegationSignatureInvalid(
                "signature or issuer is not valid hex")
        if ed25519.verify(pub, SIGN_DOMAIN + _canonical(body),
                           sig) is not True:
            raise DelegationSignatureInvalid(
                "delegation signature failed to verify")

    def verify(self, chain, action, now=None):
        """Verify a (chain, action) presentation.

        ``chain``: non-empty list of sealed delegations, root first.
        ``action``: ``{"with": <resource>, "can": <action>}``.
        Returns a signed invocation receipt on success; raises a
        machine-coded :class:`DelegationError` otherwise.
        """
        now = _check_now(time.time() if now is None else now)
        if not isinstance(chain, list) or not chain:
            raise DelegationMalformed(
                "chain must be a non-empty list")
        if not isinstance(action, dict):
            raise DelegationMalformed("action must be a dict")
        act_with = action.get("with")
        act_can = action.get("can")
        if not isinstance(act_with, str) or not act_with:
            raise DelegationMalformed(
                "action 'with' must be a non-empty string")
        if not isinstance(act_can, str) or not act_can:
            raise DelegationMalformed(
                "action 'can' must be a non-empty string")

        bodies = []
        prev_digest = None
        for i, sealed in enumerate(chain):
            body, sig_hex = _check_sealed(sealed)
            # Type is checked inside _check_sealed before any
            # interpretation of the body.
            if i == 0:
                if body["parent_digest"] is not None:
                    raise DelegationParentMismatch(
                        "root delegation must carry a null "
                        "parent_digest")
            else:
                if body["parent_digest"] != prev_digest:
                    raise DelegationParentMismatch(
                        "hop %d parent_digest does not match the "
                        "presented parent" % i)
            self._verify_signature(body, sig_hex)
            if i == 0:
                if body["issuer"] not in self._anchors:
                    raise DelegationRootUntrusted(
                        "root issuer is not in the trust anchors")
            else:
                if not _caps_covered(body["capabilities"],
                                     bodies[-1]["capabilities"]):
                    raise DelegationAttenuationInverted(
                        "hop %d grants capabilities not covered by "
                        "its parent" % i)
            if not body["not_before"] <= now <= body["not_after"]:
                raise DelegationExpired(
                    "hop %d is outside its validity window" % i)
            bodies.append(body)
            prev_digest = digest_of(body)

        leaf = bodies[-1]
        covered = any(
            _with_covered(act_with, cap["with"]) and
            (act_can in cap["can"] or "*" in cap["can"])
            for cap in leaf["capabilities"])
        if not covered:
            raise DelegationActionRefused(
                "action is not covered by the leaf capabilities")

        replay_key = (prev_digest, act_with, act_can)
        if replay_key in self._seen:
            raise DelegationReplay(
                "this (chain, action) was already verified")
        self._seen.add(replay_key)

        receipt = {
            "type": RECEIPT_TYPE,
            "chain_digest": prev_digest,
            "action": {"with": act_with, "can": act_can},
            "verified_at": now,
            "decision": "ok",
        }
        if self._seed is not None:
            receipt["signature"] = ed25519.sign(
                self._seed,
                RECEIPT_DOMAIN + _canonical(receipt)).hex()
        else:
            receipt["signature"] = None
        return receipt
