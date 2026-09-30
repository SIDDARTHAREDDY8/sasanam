"""Attested-agent-identity cross-check (W246-10, PTV direction).

A peer's agent identity is cross-checked against an attestation -- and an
UNVERIFIED anchor yields ``asserted-only``, never ``attested``.

This is the peer-verification counterpart to the bootstrap-ceremony
machinery in ``gov/attested_identity.py`` (which mints tier-1/tier-2
credentials) and the channel layer in ``gov/attested_channel.py``
(which admits emitter claims). Neither of those answers the question
this module answers: *a remote peer asserts "I am agent-7" and hands us
an attestation -- do we believe it, and on what basis?*

``check(peer_claim, attestation, anchor=None)`` grades the peer's claimed
identity against a deployment-supplied trust root::

    peer_claim  = {"principal": "agent-7", ...}   # peer's assertion
    attestation = {"attested_principal": "agent-7",
                   "key_id": "anchor-1",
                   "signature": <64-byte Ed25519>}  # anchor's vouch
    anchor      = {"keys": {"anchor-1": <32-byte pubkey>}}  # trust root

Verdicts (returned as dicts; never exceptions for the check itself):

- ``attested``: the attestation is well-formed, its Ed25519 signature
  verifies (``is True``, never assumed) against a deployment-provisioned
  anchor key, and the attested principal matches the peer's claim.
- ``asserted-only``: no attestation was presented, or the deployment
  provisioned no verifiable anchor. The claim is taken as merely
  asserted; downstream MUST treat it as untrusted. An unverified anchor
  NEVER grades attested.
- ``refused``: the attestation is malformed (fail-closed), references an
  anchor key the deployment did not provision, fails signature
  verification, or the attested principal does not match the peer's
  claim. Carries a machine ``code`` from the taxonomy.

``make_attestation(seed, key_id, attested_principal)`` mints an
attestation for the deployment/daemon side. The signature covers a
domain-separated canonical encoding of (key_id, attested_principal);
extra unsigned fields on the attestation dict are ignored by
verification (forward-compatible), never trusted.

Fail-closed discipline:
- Peer-supplied input that is malformed -> refused. A corrupt
  credential is never downgraded to asserted-only. (A peer presenting
  nothing at all is asserted-only: there is no credential to distrust.)
- Deployment config that is missing or broken (no anchor, empty key
  set) -> asserted-only. Verification is impossible, so the honest
  grade is the lower one; this can never produce ``attested``.
- ``gov.ed25519.verify`` returns True/False and never raises; the check
  requires ``is True`` (wave-243 lesson: never assume a verifier
  raises, never rely on truthiness).

Honest residuals:
- The anchor (trust root) is deployment-supplied and untrusted until
  used in a successful verification. The deployment OWNS anchor
  provisioning, rotation, and revocation; this module cannot make a
  lying or compromised anchor honest. A compromised anchor key can
  attest any principal -- anchor compromise is outside this module's
  boundary (cf. single-use-attestation revocation codes).
- No clock: attestations carry no expiry here. Freshness, replay
  protection, and single-use semantics belong to the caller (cf.
  ``gov/decision_packet.py`` chaining, single-use attestation codes).
- The check binds the principal string only. Richer claims (exe path,
  uid, kernel facts) are the attested_channel / kernel-attestation
  layer's job; this module answers "does the anchor vouch for THIS
  principal", nothing more.
- ``make_attestation`` holds the anchor seed in-process; production
  deployments must mint attestations in the key-custody boundary
  (KMS/Vault/HSM), never in the agent process.

Stdlib only (+ in-repo gov.ed25519, pure-Python). Deterministic.
"""

from gov import ed25519 as _ed25519

ATTESTED = "attested"
ASSERTED_ONLY = "asserted-only"
REFUSED = "refused"

IDENTITY_ATTESTATION_MALFORMED = "identity-attestation-malformed"
IDENTITY_ANCHOR_UNKNOWN = "identity-anchor-unknown"
IDENTITY_ATTESTATION_UNVERIFIABLE = "identity-attestation-unverifiable"
IDENTITY_CLAIM_MISMATCH = "identity-claim-mismatch"


def _canonical(key_id, attested_principal):
    """Domain-separated canonical bytes covered by the attestation."""
    kid = key_id.encode("utf-8")
    princ = attested_principal.encode("utf-8")
    return (b"attested-identity/v1\x00"
            + len(kid).to_bytes(4, "big") + kid
            + len(princ).to_bytes(4, "big") + princ)


def make_attestation(seed, key_id, attested_principal):
    """Mint an attestation dict for (key_id, attested_principal).

    Raises ValueError on programmer error (bad seed / key_id /
    principal); minting is a deployment-side operation, not a check.
    """
    if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    if not isinstance(key_id, str) or not key_id:
        raise ValueError("key_id must be a non-empty string")
    if not isinstance(attested_principal, str) or not attested_principal:
        raise ValueError("attested_principal must be a non-empty string")
    sig = _ed25519.sign(bytes(seed), _canonical(key_id, attested_principal))
    return {"attested_principal": attested_principal,
            "key_id": key_id,
            "signature": sig}


def _refused(code, detail):
    return {"verdict": REFUSED, "code": code, "detail": detail}


def _asserted_only(detail):
    return {"verdict": ASSERTED_ONLY, "code": None, "detail": detail}


def _anchor_keys(anchor):
    """Return the provisioned key map, or None when no verifiable anchor."""
    if anchor is None:
        return None
    if not isinstance(anchor, dict):
        return None
    keys = anchor.get("keys")
    if not isinstance(keys, dict) or not keys:
        return None
    return keys


def check(peer_claim, attestation, anchor=None):
    """Cross-check a peer's claimed identity against an attestation.

    Returns a dict with ``verdict`` in {"attested", "asserted-only",
    "refused"}, plus ``code`` (taxonomy refusal code or None) and a
    human ``detail``. Never raises on input shape; never grades
    ``attested`` without a verified anchor signature over a matching
    principal.
    """
    # 1. The peer claim must be well-formed; without a claim there is
    #    nothing to cross-check.
    if not isinstance(peer_claim, dict):
        return _refused(IDENTITY_ATTESTATION_MALFORMED,
                        "peer_claim is not a dict")
    principal = peer_claim.get("principal")
    if not isinstance(principal, str) or not principal:
        return _refused(IDENTITY_ATTESTATION_MALFORMED,
                        "peer_claim carries no principal string")

    # 2. No attestation presented: grade what we have, honestly.
    if attestation is None:
        return _asserted_only(
            "no attestation presented; claim taken as asserted only")

    # 3. Something was presented as an attestation but is malformed:
    #    fail closed even before consulting the anchor.
    if not isinstance(attestation, dict):
        return _refused(IDENTITY_ATTESTATION_MALFORMED,
                        "attestation is not a dict")
    attested_principal = attestation.get("attested_principal")
    key_id = attestation.get("key_id")
    signature = attestation.get("signature")
    if (not isinstance(attested_principal, str) or not attested_principal
            or not isinstance(key_id, str) or not key_id
            or not isinstance(signature, (bytes, bytearray))
            or len(signature) != 64):
        return _refused(IDENTITY_ATTESTATION_MALFORMED,
                        "attestation failed structural validation")

    # 4. No verifiable anchor: an unverified anchor yields asserted-only,
    #    never attested. (Deployment owns anchor provisioning.)
    keys = _anchor_keys(anchor)
    if keys is None:
        return _asserted_only(
            "no verifiable anchor provisioned; claim taken as asserted "
            "only")

    # 5. The attestation must reference a provisioned anchor key.
    pub = keys.get(key_id)
    if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
        return _refused(IDENTITY_ANCHOR_UNKNOWN,
                        "anchor key %r not provisioned or malformed" % (
                            key_id,))

    # 6. The anchor's signature must verify. gov.ed25519.verify returns
    #    True/False and never raises; require ``is True`` (wave-243).
    msg = _canonical(key_id, attested_principal)
    ok = _ed25519.verify(bytes(pub), msg, bytes(signature))
    if ok is not True:
        return _refused(IDENTITY_ATTESTATION_UNVERIFIABLE,
                        "anchor signature failed verification")

    # 7. The attested principal must match the peer's claim.
    if attested_principal != principal:
        return _refused(IDENTITY_CLAIM_MISMATCH,
                        "anchor attests %r but peer claims %r" % (
                            attested_principal, principal))

    return {"verdict": ATTESTED, "code": None,
            "detail": "anchor %r vouches for principal %r" % (
                key_id, principal)}
