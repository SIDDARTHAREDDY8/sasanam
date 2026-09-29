"""A2A v1 signed Agent Card verifier (row-11 cross-runtime identity).

The identity-proof layer for A2A-speaking counterparties: verifies a
foreign agent's signed Agent Card BEFORE its key is admitted into the
delegation trust roster. The card proves WHO the key belongs to; the
delegation receipt (gov/delegation_tokens.py) remains the
authorization layer.

Verifier construction (A2A spec v1.0.0, 2026-03-12, section 8.4):

  1. Canonical payload = RFC 8785 (JCS) canonical JSON of the card
     MINUS the ``signatures`` field, with proto field-presence rules
     (unset/None fields omitted).
  2. JWS flattened/detached style: each ``signatures[]`` entry carries
     ``protected`` = base64url(JSON header) and ``signature`` =
     base64url over ``base64url(protected) + "." +
     base64url(canonical-payload)``. The payload is never transmitted
     inside the JWS; the verifier re-canonicalizes the card body.
  3. Protected header: ``alg``, ``typ: "JOSE"``, ``kid``, optional
     ``jku``.

Signature primitive (v1): **EdDSA (Ed25519) via gov/ed25519.py** — the
repo's own RFC 8032 implementation, already the signature primitive
for delegation tokens ("Ed25519 everywhere, no PKI"). ``verify()``
never raises on malformed inputs (fail-closed: malformed is False).

Honest v1 boundary — ES256 refused: the strict allow-list is
``{"EdDSA"}``; a card signed with ES256 (or any other alg, including
``"none"``) is refused with ``unsupported-alg``. The ``cryptography``
package is NOT in requirements.lock and installing it would trip the
F75 supply-chain gate (unlisted dist fails the canonical suite
closed); until a vetted ECDSA implementation lands, ES256 cards are
fail-closed, not degraded. This is a documented refusal, not silent
non-support.

Trust model (fail-closed):

  - Keys come ONLY from a pinned deployment ``CardTrustStore``:
    ``{kid: {pubkey, alg, jku, fetched_at, owner}}``. The verifier NEVER
    fetches. There is no network path in this module at all —
    key-substitution via jku is structurally impossible.
  - A ``jku`` in the protected header is policy-checked, never
    fetched: must be ``https://``, must be on the deployment
    allow-list, and must equal the ``jku`` recorded for that ``kid``
    in the trust store. Any mismatch is key-substitution and is
    refused.
  - Trust records carry ``fetched_at``; records older than
    ``max_key_age_s`` are refused (``stale-trust``) — rotation is a
    deployment act, not silent acceptance.
  - The A2A spec version is pinned to exactly ``"1.0"``
    (``PINNED_A2A_VERSIONS``): 0.2->0.3->1.0 broke inside a year, and
    most online guidance is v0.x. Anything else is ``card-version``.
  - The card record must carry the inventory shape (``agent_id``,
    ``name``, ``version``, ``capabilities``, ``endpoints``, ``keys``)
    or it is ``malformed-card`` — a well-formed record is checked
    before any signature is examined.
  - ``expires`` is required; past expiry is ``expired-card`` and a
    future ``issued_at`` is ``not-yet-valid``. Stale cards never
    verify.
  - A trust record MAY pin an ``owner`` (the agent_id the kid belongs
    to); the card's ``agent_id`` must equal it or the card is
    ``identity-mismatch``. This is the kid-swap refusal: an attacker
    re-signing a victim's card under their own pinned kid cannot
    launder the victim's identity.

A2A divergence, documented (a2a-go issue #445): the Go SDK skips
§8.4.1 rule-1 proto projection, so SDK-signed cards do not
cross-verify with the JS SDK. We implement NEITHER projection: we JCS
the whole card body minus ``signatures``, so unknown/extra fields ARE
covered by our signature (whereas under rule-1-conformant verifiers
they are not). Our cards never leave this canonical form, and any
A2A SDK output is treated as untrusted input.

``register_agent_card`` bridges verification and the delegation
roster: on success the verified ``(identity, kid, pubkey)`` is
registered into ``DelegationTrust.card_identities`` (identity-proof
layer) and — for Ed25519 card keys — into
``DelegationTrust.agent_keys`` keyed by the card's ``name``, so the
foreign agent can parent-sign sub-delegations with its card key (the
``_roster_for_depth`` check then works for its spawn lineage).

Distinct failure codes (the Decision+Diagnostics bar needs the
attribution — not a single generic "no valid signatures"):
``missing-signatures`` / ``malformed-signature-entry`` /
``unsupported-alg`` / ``kid-ambiguity`` / ``untrusted-jku`` /
``stale-trust`` / ``invalid-signature`` / ``canonicalization-failure``
/ ``identity-mismatch`` / ``malformed-card`` / ``card-version`` /
``expired-card`` / ``not-yet-valid``.

$0 spend, synthetic/local only. No credentials, no network.
"""

import base64
import json
import time

from . import ed25519 as _ed

# v1 strict allow-list. ES256 is refused (unsupported-alg) until a
# vetted ECDSA implementation is available — see the module docstring.
ALLOWED_ALGS = frozenset({"EdDSA"})
REQUIRED_TYP = "JOSE"

# A2A spec version pin. The spec churned 0.2 -> 0.3 -> 1.0 breaking
# inside a year and most online guidance is v0.x; cards are accepted
# ONLY with a2a_version exactly "1.0" (wave-214 lane A ADAPT).
A2A_SPEC_VERSION = "1.0"
PINNED_A2A_VERSIONS = frozenset({A2A_SPEC_VERSION})

# The inventory card record shape (wave-214 ADAPT): a signed card must
# carry ``agent_id``, ``name``, ``version``, ``capabilities``,
# ``endpoints``, and ``keys`` (enforced by _check_card_shape).
# ``signatures`` is handled separately; ``a2a_version`` and
# ``issued_at``/``expires`` are checked by dedicated rules below.

# Trust records older than this are refused (rotation = deployment act).
DEFAULT_MAX_KEY_AGE_S = 86400


class CardVerificationError(Exception):
    """Fail-closed card verification failure. ``code`` is the distinct
    failure mode; ``detail`` carries the attribution for diagnostics."""

    def __init__(self, code, detail=""):
        super().__init__("%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


# ---------------------------------------------------------------------------
# Canonical JSON (RFC 8785 / JCS style)
# ---------------------------------------------------------------------------

def _normalize_numbers(value):
    """JCS number rule: integral floats serialize as integers.

    Python's json.dumps(1.0) -> "1.0"; JCS requires "1". Normalizing
    integral floats to int before serialization matches what a
    JCS-conformant signer hashed. Non-integral floats keep Python's
    shortest-round-trip repr, which matches JCS.
    """
    if isinstance(value, dict):
        return {k: _normalize_numbers(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize_numbers(v) for v in value]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def canonical_card_json(card):
    """RFC 8785-style canonical JSON of the card minus ``signatures``.

    sorted keys, no whitespace, UTF-8 (ensure_ascii=False), unset/None
    fields omitted (proto field-presence rule), ``allow_nan=False`` so
    non-finite floats fail closed instead of emitting ``Infinity``.
    Raises CardVerificationError("canonicalization-failure") on any
    non-object or non-serializable input — never a silent mismatch.
    """
    if not isinstance(card, dict):
        raise CardVerificationError("canonicalization-failure",
                                    "card body is not a JSON object")
    body = {k: v for k, v in card.items()
            if k != "signatures" and v is not None}
    body = _normalize_numbers(body)
    try:
        text = json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise CardVerificationError("canonicalization-failure",
                                    "card body not canonicalizable: %s"
                                    % exc)
    return text.encode("utf-8")


def _b64u_encode(data):
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def _b64u_decode(text):
    if not isinstance(text, str) or not text:
        raise CardVerificationError(
            "malformed-signature-entry",
            "protected/signature must be non-empty base64url strings")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except Exception as exc:
        raise CardVerificationError("malformed-signature-entry",
                                    "base64url decode failed: %s" % exc)


# ---------------------------------------------------------------------------
# Pinned card trust store (deployment-controlled, offline-root model)
# ---------------------------------------------------------------------------

class CardTrustStore(object):
    """The deployment's pinned Agent Card verification keys.

    ``keys``: ``{kid: {"pubkey": 32-byte Ed25519 pub, "alg": "EdDSA",
    "jku": <https url> | None, "fetched_at": <epoch seconds>}}``.
    ``jku_allowlist``: the only jku values a protected header may name
    (policy-checked, never fetched).

    Registration is a deployment act: bad records raise ValueError
    fail-fast (fail fast at registration, fail closed at verification).
    """

    def __init__(self, keys=None, jku_allowlist=()):
        self.keys = {}
        for kid, rec in (keys or {}).items():
            self.register_key(kid, **rec)
        allow = []
        for url in jku_allowlist or ():
            if not isinstance(url, str) or not url:
                raise ValueError("jku_allowlist entries must be "
                                 "non-empty strings")
            allow.append(url)
        self.jku_allowlist = frozenset(allow)

    def register_key(self, kid, pubkey, alg="EdDSA", jku=None,
                     fetched_at=0, owner=None):
        """Pin (or rotate) a card verification key. Rotation =
        re-registration, an audited deployment act.

        ``owner`` (optional): the ``agent_id`` this kid is pinned to.
        When set, verify_card refuses any card whose ``agent_id`` does
        not equal it (``identity-mismatch``) — this is the kid-swap
        refusal: an attacker re-signing a victim's card under their own
        kid cannot launder the victim's identity.
        """
        if not isinstance(kid, str) or not kid:
            raise ValueError("kid must be a non-empty string")
        if isinstance(pubkey, str):
            try:
                pubkey = bytes.fromhex(pubkey)
            except ValueError:
                raise ValueError("pubkey: not hex")
        if not isinstance(pubkey, (bytes, bytearray)) or len(pubkey) != 32:
            raise ValueError("pubkey must be a 32-byte Ed25519 public key")
        if alg != "EdDSA":
            # v1: only Ed25519 card keys can be pinned (the verifier's
            # allow-list is EdDSA-only; pinning an unverifiable alg
            # would be theater).
            raise ValueError("alg %r not supported in v1 (EdDSA only)"
                             % (alg,))
        if jku is not None and (not isinstance(jku, str) or not jku):
            raise ValueError("jku must be a non-empty string or None")
        if (isinstance(fetched_at, bool)
                or not isinstance(fetched_at, (int, float))
                or fetched_at < 0):
            raise ValueError("fetched_at must be a non-negative epoch")
        if owner is not None and (not isinstance(owner, str) or not owner):
            raise ValueError("owner must be a non-empty string or None")
        self.keys[kid] = {"pubkey": bytes(pubkey), "alg": alg, "jku": jku,
                          "fetched_at": float(fetched_at), "owner": owner}

    def describe(self):
        """Safe public description — kids only, never key material."""
        return {"kids": sorted(self.keys),
                "jku_allowlist": sorted(self.jku_allowlist)}


# ---------------------------------------------------------------------------
# Inventory card shape, version pin, and lifetime (wave-214 ADAPT)
# ---------------------------------------------------------------------------

def _check_card_shape(card):
    """Enforce the inventory card record shape.

    Required: agent_id, name, version (non-empty strings);
    capabilities (list), keys (list of {kid,...} dicts);
    endpoints (dict or list). Fail-closed: ``malformed-card``.
    """
    for field in ("agent_id", "name", "version"):
        value = card.get(field)
        if not isinstance(value, str) or not value:
            raise CardVerificationError(
                "malformed-card",
                "card field %r must be a non-empty string" % (field,))
    capabilities = card.get("capabilities")
    if not isinstance(capabilities, list):
        raise CardVerificationError(
            "malformed-card",
            "card field 'capabilities' must be a list")
    endpoints = card.get("endpoints")
    if not isinstance(endpoints, (dict, list)):
        raise CardVerificationError(
            "malformed-card",
            "card field 'endpoints' must be a dict or list")
    keys = card.get("keys")
    if not isinstance(keys, list) or not keys:
        raise CardVerificationError(
            "malformed-card",
            "card field 'keys' must be a non-empty list")
    for entry in keys:
        if (not isinstance(entry, dict)
                or not isinstance(entry.get("kid"), str)
                or not entry.get("kid")):
            raise CardVerificationError(
                "malformed-card",
                "card keys[] entries must carry a non-empty kid")


def _check_card_version(card):
    """The A2A spec version is pinned to exactly "1.0" — no negotiation,
    no range matching. Fail-closed: ``card-version``."""
    version = card.get("a2a_version")
    if version not in PINNED_A2A_VERSIONS:
        raise CardVerificationError(
            "card-version",
            "a2a_version %r not in the pinned set %s "
            "(spec churn 0.2->0.3->1.0; only 1.0 accepted)"
            % (version, sorted(PINNED_A2A_VERSIONS)))


def _check_card_lifetime(card, now):
    """``expires`` is REQUIRED and numeric; past expiry refuses
    (``expired-card``). A future ``issued_at`` refuses (``not-yet-valid``)
    — a card must not verify before it exists. Fail-closed on
    non-numeric values (``malformed-card``)."""
    expires = card.get("expires")
    if (isinstance(expires, bool)
            or not isinstance(expires, (int, float))):
        raise CardVerificationError(
            "malformed-card",
            "card field 'expires' must be a numeric epoch")
    if now > expires:
        raise CardVerificationError(
            "expired-card",
            "card expired %ds ago (stale cards never verify)"
            % (now - expires,))
    issued_at = card.get("issued_at")
    if issued_at is not None:
        if (isinstance(issued_at, bool)
                or not isinstance(issued_at, (int, float))):
            raise CardVerificationError(
                "malformed-card",
                "card field 'issued_at' must be a numeric epoch or absent")
        if now < issued_at:
            raise CardVerificationError(
                "not-yet-valid",
                "card not valid until %ds in the future" % (issued_at - now,))


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def _check_jku(jku, kid, store):
    """The header jku is policy-checked, never fetched."""
    if not isinstance(jku, str) or not jku.startswith("https://"):
        raise CardVerificationError("untrusted-jku",
                                    "kid %r: jku must be an https URL"
                                    % (kid,))
    if jku not in store.jku_allowlist:
        raise CardVerificationError(
            "untrusted-jku",
            "kid %r: jku %r not on the deployment allow-list "
            "(no fetch attempted)" % (kid, jku))
    recorded = store.keys[kid].get("jku")
    if recorded != jku:
        raise CardVerificationError(
            "untrusted-jku",
            "kid %r: header jku does not match the trust-store record "
            "(key-substitution refused)" % (kid,))


def _verify_one_signature(kid, pubkey, signing_input, signature_b64):
    """Ed25519 verify; malformed signature bytes are False, never an
    exception (gov.ed25519.verify is fail-closed by contract)."""
    try:
        sig = _b64u_decode(signature_b64) if signature_b64 else None
    except CardVerificationError:
        return False
    if sig is None:
        return False
    return _ed.verify(pubkey, signing_input, sig)


def verify_card(card, store, *, expected_identity=None,
                max_key_age_s=DEFAULT_MAX_KEY_AGE_S, now=None):
    """Verify a signed Agent Card against the pinned store.

    Returns ``{"identity": <card name>, "kids": [verified kids]}``.
    Fail-closed: raises CardVerificationError with a distinct code on
    every failure mode. Requires at least one fully valid signature.
    When ``expected_identity`` is given, the card's ``name`` must equal
    it (``identity-mismatch``) — the verified key does not bind to a
    different receipt identity.
    """
    now = time.time() if now is None else now
    if not isinstance(card, dict):
        raise CardVerificationError("canonicalization-failure",
                                    "card body is not a JSON object")
    if not isinstance(store, CardTrustStore):
        raise TypeError("store must be a CardTrustStore")

    # The card record must be a well-formed, pinned-version, live
    # inventory record BEFORE any signature is examined: shape, version,
    # and lifetime failures are distinct from signature failures.
    _check_card_shape(card)
    _check_card_version(card)
    _check_card_lifetime(card, now)

    sigs = card.get("signatures")
    if not sigs or not isinstance(sigs, list):
        raise CardVerificationError("missing-signatures",
                                    "card carries no signatures[]")

    canonical = canonical_card_json(card)
    seen_kids = set()
    valid_kids = []

    for entry in sigs:
        if not isinstance(entry, dict):
            raise CardVerificationError("malformed-signature-entry",
                                        "signature entry is not an object")
        protected_b64 = entry.get("protected")
        signature_b64 = entry.get("signature")
        if not protected_b64:
            raise CardVerificationError("malformed-signature-entry",
                                        "missing protected header")
        protected_bytes = _b64u_decode(protected_b64)
        try:
            header = json.loads(protected_bytes.decode("utf-8"))
        except Exception as exc:
            raise CardVerificationError("malformed-signature-entry",
                                        "protected header is not JSON: %s"
                                        % exc)
        if not isinstance(header, dict):
            raise CardVerificationError("malformed-signature-entry",
                                        "protected header is not an object")

        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:
            raise CardVerificationError(
                "unsupported-alg",
                "alg %r not in the strict allow-list %s (no negotiation, "
                "no downgrade; ES256 is a documented v1 refusal)"
                % (alg, sorted(ALLOWED_ALGS)))
        if header.get("typ") != REQUIRED_TYP:
            raise CardVerificationError("malformed-signature-entry",
                                        "typ must be %r" % (REQUIRED_TYP,))

        kid = header.get("kid")
        if not kid or not isinstance(kid, str):
            raise CardVerificationError("kid-ambiguity", "missing kid")
        if kid in seen_kids:
            raise CardVerificationError(
                "kid-ambiguity",
                "duplicate kid %r in signatures[]" % (kid,))
        seen_kids.add(kid)

        keyrec = store.keys.get(kid)
        if keyrec is None:
            raise CardVerificationError(
                "kid-ambiguity",
                "kid %r not in the pinned trust store" % (kid,))

        # Kid-pinned identity binding: when the deployment pinned this
        # kid to an owner agent_id, the card's agent_id must equal it.
        # An attacker re-signing a victim's card under their own kid
        # cannot launder the victim's identity (identity-mismatch).
        owner = keyrec.get("owner")
        if owner is not None and card.get("agent_id") != owner:
            raise CardVerificationError(
                "identity-mismatch",
                "kid %r is pinned to agent %r; card claims %r "
                "(kid-swap refused)" % (kid, owner, card.get("agent_id")))

        jku = header.get("jku")
        if jku is not None:
            _check_jku(jku, kid, store)

        if now - keyrec["fetched_at"] > max_key_age_s:
            raise CardVerificationError(
                "stale-trust",
                "kid %r: trust data older than %ds (rotation is a "
                "deployment act)" % (kid, max_key_age_s))

        signing_input = (protected_b64.encode("ascii") + b"." +
                         _b64u_encode(canonical).encode("ascii"))
        if not _verify_one_signature(kid, keyrec["pubkey"], signing_input,
                                     signature_b64):
            raise CardVerificationError(
                "invalid-signature",
                "kid %r: signature does not verify over the "
                "re-canonicalized payload" % (kid,))
        valid_kids.append(kid)

    if not valid_kids:
        raise CardVerificationError("invalid-signature",
                                    "no valid signatures found")

    identity = card.get("name")
    if expected_identity is not None and identity != expected_identity:
        raise CardVerificationError(
            "identity-mismatch",
            "card identity %r != expected %r (verified key does not bind "
            "to this receipt)" % (identity, expected_identity))

    return {"identity": identity, "kids": valid_kids}


def sign_card(card, kid, seed, *, jku=None, alg="EdDSA"):
    """Test helper: produce a signatures[] entry for a synthetic card.

    ``seed`` is the 32-byte Ed25519 seed (test-only; never production
    key material). Mirrors the verifier's canonicalization exactly so
    the battery tests the pipeline, not a signing/verifying skew.
    """
    if alg != "EdDSA":
        raise ValueError("sign_card test helper signs EdDSA only")
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    header = {"alg": alg, "typ": "JOSE", "kid": kid}
    if jku is not None:
        header["jku"] = jku
    protected_b64 = _b64u_encode(json.dumps(
        header, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    canonical = canonical_card_json(card)
    signing_input = (protected_b64.encode("ascii") + b"." +
                     _b64u_encode(canonical).encode("ascii"))
    sig = _ed.sign(bytes(seed), signing_input)
    return {"protected": protected_b64, "signature": _b64u_encode(sig)}


def emit_card(card_fields, kid, seed, *, jku=None, alg="EdDSA",
              issued_at=None, expires_in_s=86400, now=None):
    """Production card emission: build the inventory card record, pin the
    A2A spec version, stamp the lifetime, validate the shape, and sign.

    ``card_fields`` must carry the record shape: ``agent_id``, ``name``,
    ``version`` (the AGENT's version — the A2A spec version is pinned
    separately), ``capabilities`` (list), ``endpoints`` (dict or list),
    ``keys`` (non-empty list of {kid,...}). ``seed`` is the issuer's
    32-byte Ed25519 seed — production callers hold it in the deployment
    trust domain (never agent-supplied, never logged).

    Returns the full card dict including ``signatures``. Deterministic:
    identical inputs yield byte-identical output (Ed25519 is
    deterministic; JCS canonicalization is fixed).

    Fail-fast: shape violations raise CardVerificationError BEFORE any
    signing (an unsigned malformed card must never exist either).
    """
    now = time.time() if now is None else now
    card = dict(card_fields)
    # Defaults only: a caller-supplied value (including an attacker's in
    # tests) is preserved so the verifier's checks stay meaningful.
    card.setdefault("a2a_version", A2A_SPEC_VERSION)
    card.setdefault("issued_at", now if issued_at is None else issued_at)
    card.setdefault("expires", now + expires_in_s)
    _check_card_shape(card)
    _check_card_version(card)
    _check_card_lifetime(card, now)
    card["signatures"] = [sign_card(card, kid, seed, jku=jku, alg=alg)]
    return card


def register_agent_card(delegation_trust, card, store, *, now=None):
    """Verify an Agent Card and admit its identity into the delegation
    roster. THE registration seam: the only way a foreign agent's key
    enters ``DelegationTrust``.

    On success:
      - ``delegation_trust.card_identities[identity]["kids"][kid]`` =
        ``{"pubkey", "alg"}`` for every verified kid (identity-proof
        layer; ``verify_delegation_chain`` enforces the ``card_kid``
        binding against this registry).
      - ``delegation_trust.agent_keys[identity]`` = the first verified
        kid's Ed25519 pubkey, so the foreign agent can parent-sign
        sub-delegations with its card key (the ``_roster_for_depth``
        check works for its spawn lineage).

    A forged card (wrong key, unknown kid, tampered body, untrusted
    jku, stale trust, bad alg) is refused here with the verifier's
    distinct code — the key never reaches the roster. Returns
    ``{"identity", "kids"}``.
    """
    result = verify_card(card, store, now=now)
    identity = result["identity"]
    if not isinstance(identity, str) or not identity:
        raise CardVerificationError(
            "identity-mismatch",
            "card carries no name: nothing to bind the verified key to")
    for i, kid in enumerate(result["kids"]):
        pubkey = store.keys[kid]["pubkey"]
        delegation_trust.register_card_identity(identity, kid, pubkey,
                                                "EdDSA")
        if i == 0:
            # The card key IS an Ed25519 key: the foreign agent's
            # parent-signing key for its spawn lineage.
            delegation_trust.agent_keys[identity] = bytes(pubkey)
    return result
