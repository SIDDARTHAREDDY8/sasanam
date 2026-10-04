"""Agent identity: every action the governance layer sees is attributed.

F17b: principal rotation. An attacker who can mint identities for
arbitrary principal strings can trivially shed ledger taint by rotating
to a fresh principal ("org2"). No in-band check on the string itself can
fix that — the fix is deployment-controlled issuance: a
``PrincipalRegistry`` of pre-registered principals, consulted by
``ToolExecutor.mint_identity``. In registry mode an unregistered
principal raises ``UnregisteredPrincipalError`` and every issuance is
audit-logged (``identity_minted``). With no registry configured the
executor stays permissive (any string mints): that is an explicit
deployment-trust residual — the demo's default — not a control.

F50 (R12): the registry is now a real identity trust anchor, not just a
principal allowlist. Each principal maps to the roles it may mint (and
optionally the agent_ids it may use); in registry mode
``mint_identity`` refuses any (principal, role[, agent_id]) pair the
registry does not authorize, and the refusal is audit-logged
(``identity_mint_refused``). With no registry the executor still mints
freely but emits a loud one-time stderr warning that identity is
self-asserted (same disclosure pattern as the dev-key warnings).

F55 (R13): minting authenticates nothing about the CALLER — in-process
code holding the executor can mint the registered operator tuple and
consume a human-provisioned break-glass ticket as the operator (the F26
verifier checks mintedness, never entitlement). The fix separates the
session identity from mintable identities: the deployment provisions
exactly ONE session identity at ``ToolExecutor`` construction
(``session_identity=(agent_id, role, principal)``); it is created with
``provenance="provisioned"`` while ``mint_identity`` issues
``provenance="minted"``. ``ApprovalQueue.break_glass`` requires the
provisioned session identity and refuses mid-run mints with an audited
``break_glass_refused`` entry. Without a provisioned session identity
the pre-R13 behavior (F26 mintedness check) is kept, with the existing
self-asserted warnings.
"""

import json
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone


class UnmintedIdentityError(Exception):
    """Raised when an identity object was not issued by the executor."""


class UnregisteredPrincipalError(Exception):
    """Raised when minting for a principal the registry does not know."""


class UnregisteredRoleError(UnregisteredPrincipalError):
    """F50: raised when minting a (principal, role) or
    (principal, agent_id) pair the registry does not authorize.

    A subclass of ``UnregisteredPrincipalError`` so existing handlers
    that catch registry refusals keep working.
    """


class IdentityMintLimitError(Exception):
    """Raised when a run exhausts its identity issuance budget."""


class IdentityTokenError(Exception):
    """A presented identity token failed validation (loud, fail-closed).

    Raised by ``ToolExecutor.mint_identity`` when ``token_claims`` are
    supplied but the claim set is malformed, expired, mis-audienced, or
    disagrees with the requested identity fields. The JWT signature
    itself is the deployment dex client's job (verified against the
    pinned issuer JWKS before the claim set reaches this seam); this
    enforces the claim policy on what was presented.

    ``code`` is the optional machine decision code (wave-325 lane 2:
    the federated-mode ``identity-token-required`` refusal carries
    one); None = legacy un-coded refusal.
    """

    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


# F50: one-time loud disclosure that identity is self-asserted when no
# registry is configured (same pattern as the dev-key warnings in
# gov/log.py). Per-process, resettable by tests.
_self_asserted_warned = False


def warn_self_asserted_identity_once():
    """Print the self-asserted-identity warning to stderr, once per
    process. Called by ``ToolExecutor.mint_identity`` in dev mode (no
    registry configured)."""
    global _self_asserted_warned
    if _self_asserted_warned:
        return
    _self_asserted_warned = True
    print(
        "GOVERNANCE WARNING: no PrincipalRegistry configured — agent "
        "identity is SELF-ASSERTED. mint_identity() authenticates nothing "
        "about the caller: any in-process code can mint any agent_id, "
        "role, and principal, and audit attribution is only as strong as "
        "the process boundary. Configure a deployment-controlled "
        "PrincipalRegistry (principal -> allowed roles) for real "
        "deployments.",
        file=sys.stderr)


class PrincipalRegistry:
    """Deployment-controlled identity trust anchor (F17b, extended F50).

    ``principals`` is the set of principal strings this deployment
    recognizes (tenants, teams, service accounts). Registration is an
    out-of-band admin act — the registry is constructed from deployment
    configuration, never from agent input. ``check`` is called by
    ``ToolExecutor.mint_identity`` before any identity is issued.

    F50: the registry now maps each principal to the roles it is
    allowed to mint (and optionally the agent_ids it may use), making
    it a real trust anchor for the whole identity tuple instead of a
    principal-only allowlist. Three constructor forms are accepted:

    * ``PrincipalRegistry({"a", "b"})`` — legacy: principals with
      UNRESTRICTED roles/agent_ids (the F17b behavior);
    * ``PrincipalRegistry({"a": ["coder", "researcher"]})`` — each
      principal maps to its allowed roles;
    * ``PrincipalRegistry({"a": {"roles": [...], "agent_ids": [...]}})``
      — full form; either key may be omitted for "unrestricted".

    ``check_identity(principal, role, agent_id=None)`` raises
    ``UnregisteredPrincipalError`` for unknown principals and for an
    agent_id the registry does not authorize, and the distinct
    subclass ``UnregisteredRoleError`` for a role the registry does
    not authorize.
    """

    def __init__(self, principals):
        if not principals:
            raise ValueError("PrincipalRegistry needs at least one "
                             "registered principal")
        auth = {}
        if isinstance(principals, dict):
            items = principals.items()
        else:
            items = ((p, None) for p in principals)
        for principal, spec in items:
            if not isinstance(principal, str) or not principal.strip():
                raise ValueError(
                    "PrincipalRegistry: principal names must be "
                    "non-empty strings, got %r" % (principal,))
            roles, agent_ids = None, None
            if spec is not None:
                if isinstance(spec, dict):
                    roles = spec.get("roles")
                    agent_ids = spec.get("agent_ids")
                    unknown = set(spec) - {"roles", "agent_ids"}
                    if unknown:
                        raise ValueError(
                            "PrincipalRegistry: unknown keys %r for "
                            "principal %r (allowed: roles, agent_ids)"
                            % (sorted(unknown), principal))
                elif isinstance(spec, (list, tuple)):
                    roles = spec
                else:
                    raise ValueError(
                        "PrincipalRegistry: authorization for principal "
                        "%r must be a role list or a "
                        "{'roles': [...], 'agent_ids': [...]} mapping, "
                        "got %r" % (principal, spec))
                if roles is not None:
                    roles = self._clean_str_list(
                        roles, "roles", principal)
                if agent_ids is not None:
                    agent_ids = self._clean_str_list(
                        agent_ids, "agent_ids", principal)
            auth[principal] = {"roles": roles, "agent_ids": agent_ids}
        self._auth = auth

    @staticmethod
    def _clean_str_list(values, what, principal):
        if not isinstance(values, (list, tuple)) or not values:
            raise ValueError(
                "PrincipalRegistry: %s for principal %r must be a "
                "non-empty list of strings" % (what, principal))
        out = []
        for v in values:
            if not isinstance(v, str) or not v.strip():
                raise ValueError(
                    "PrincipalRegistry: %s for principal %r must be "
                    "non-empty strings, got %r" % (what, principal, v))
            out.append(v.strip())
        return frozenset(out)

    def check(self, principal):
        """Raise ``UnregisteredPrincipalError`` for unknown principals."""
        if principal not in self._auth:
            raise UnregisteredPrincipalError(
                "principal %r is not registered with this deployment; "
                "fresh-principal rotation is not issuance" % (principal,))
        return True

    def check_identity(self, principal, role, agent_id=None):
        """F50: authorize a full (principal, role[, agent_id]) mint.

        Raises ``UnregisteredPrincipalError`` for unknown principals
        and for a registered principal minting an agent_id outside
        its registry authorization; raises the distinct subclass
        ``UnregisteredRoleError`` for a role outside the registry
        authorization. Callers can therefore tell "wrong role" apart
        from "wrong agent id / unknown principal".
        """
        self.check(principal)
        spec = self._auth[principal]
        roles = spec["roles"]
        if roles is not None and role not in roles:
            raise UnregisteredRoleError(
                "role %r is not authorized for principal %r by this "
                "deployment's registry (allowed: %s); self-asserted "
                "roles are not issuance" % (
                    role, principal, sorted(roles)))
        agent_ids = spec["agent_ids"]
        if (agent_ids is not None and agent_id is not None
                and agent_id not in agent_ids):
            raise UnregisteredPrincipalError(
                "agent_id %r is not authorized for principal %r by this "
                "deployment's registry (allowed: %s); fresh agent-id "
                "rotation is not issuance" % (
                    agent_id, principal, sorted(agent_ids)))
        return True

    def allowed_roles(self, principal):
        """The role set authorized for *principal*, or None for
        unrestricted. Raises ``UnregisteredPrincipalError`` for unknown
        principals."""
        self.check(principal)
        roles = self._auth[principal]["roles"]
        return None if roles is None else set(roles)

    def registered(self):
        """The registered principal set (for audit/debugging)."""
        return set(self._auth)


@dataclass(frozen=True)
class AgentIdentity:
    """Who acted.

    agent_id:  stable id of the agent instance, e.g. "scout-01"
    role:      the agent's job in the run, e.g. "scout"
    run_id:    the workflow run this agent belongs to
    principal: the human (or org) on whose behalf the agent acts

    F55 (R13): ``provenance`` records HOW the identity came into
    being. ``"provisioned"`` = the deployment-provisioned session
    identity, established out-of-band and created exactly once at
    ``ToolExecutor`` construction; ``"minted"`` = issued mid-run by
    ``ToolExecutor.mint_identity``. Entitlement-sensitive paths
    (``ApprovalQueue.break_glass``) require the provisioned session
    identity — a mid-run mint of the same (agent_id, role,
    principal) tuple is NOT equal to it, so tuple-equality can no
    longer impersonate the operator. The field has a default, so
    existing four-argument constructions keep working (they get
    ``"minted"``, the honest label for anything the mint path
    produces).
    """

    agent_id: str
    role: str
    run_id: str
    principal: str
    provenance: str = "minted"

    def as_dict(self):
        return asdict(self)


# ---------------------------------------------------------------------------
# Remote-attestation evidence for agent identity (Coker et al.,
# "Principles of Remote Attestation", LITERATURE IMPLEMENT item).
#
# Coker's five principles, mapped to this codebase:
# 1. Fresh evidence -- every attestation carries a verifier-supplied
#    ``nonce`` (challenge) and an ``issued_at`` timestamp;
#    ``verify_attestation`` checks both when the caller supplies the
#    expected nonce / a max age. A replayed attestation fails freshness.
# 2. Comprehensive measurement -- the claims SHOULD cover what the
#    deployment can measure (code digest, config digest, tool-policy
#    digest); this module defines the envelope and verifies the
#    signature + freshness, it does not invent measurements.
# 3. Constrained disclosure -- only the claims listed in the
#    attestation are disclosed, nothing ambient; claims are flat
#    str->str pairs, never nested blobs.
# 4. Explicit claim semantics -- ``build_attestation`` documents
#    exactly what is and is NOT attested (see below).
# 5. Trustworthy mechanism -- the evidence is Ed25519-signed by the
#    deployment-held attestation key; verifiers check it against an
#    out-of-band trusted key set (same trust model as the offline root
#    in gov/signing.py).
#
# WHAT IS ATTESTED: that the holder of the attestation key asserted,
# at ``issued_at``, the binding (agent identity tuple, claim digests,
# nonce). WHAT IS NOT: code integrity (a ``code_digest`` claim is a
# deployment-computed digest, NOT a hardware measured-boot value --
# there is no TPM here and this module must not imply one); principal
# authorization (that remains the PrincipalRegistry's job); log
# integrity (the audit log's job). An attestation says WHO claims to
# act and WHAT they claim about their configuration, freshly -- it
# does not say the claims are true.
# ---------------------------------------------------------------------------

_ATTESTATION_VERSION = 1
_ATTESTATION_DOMAIN = b"gov-attestation/v1\x00"


def build_attestation(identity, claims, nonce, signer):
    """Build signed attestation evidence for an agent identity.

    ``identity``: AgentIdentity (or its ``as_dict()``). ``claims``: flat
    dict of str->str, e.g. ``{"code_digest": ..., "config_digest":
    ..., "tool_policy_digest": ...}`` -- ONLY these claims are
    disclosed (constrained disclosure). ``nonce``: the verifier's
    freshness challenge (str). ``signer``: a ``gov.signing.Signer``
    (the deployment-held attestation key).

    Returns the attestation dict (JSON-serializable). Raises
    ValueError/TypeError on malformed inputs -- never build evidence
    over doubtful claims.
    """
    from . import signing as _signing  # local import: identity.py is
    # imported by executor-adjacent modules; keep the dependency lazy.
    if hasattr(identity, "as_dict"):
        identity = identity.as_dict()
    if not isinstance(identity, dict):
        raise TypeError("identity must be an AgentIdentity or dict")
    for field in ("agent_id", "role", "run_id", "principal"):
        if not isinstance(identity.get(field), str) \
                or not identity[field]:
            raise ValueError(
                "identity field %r missing or not a string" % field)
    if not isinstance(claims, dict) or not claims:
        raise ValueError("claims must be a non-empty dict")
    for k, v in claims.items():
        if not isinstance(k, str) or not isinstance(v, str):
            raise ValueError(
                "claims must be flat str->str (constrained disclosure)")
    if not isinstance(nonce, str) or not nonce:
        raise ValueError("nonce must be a non-empty string")
    if not isinstance(signer, _signing.Signer):
        raise TypeError("signer must be a gov.signing.Signer")
    body = {
        "attestation_version": _ATTESTATION_VERSION,
        "identity": {f: identity[f] for f in
                     ("agent_id", "role", "run_id", "principal",
                      "provenance") if f in identity},
        "claims": dict(claims),
        "nonce": nonce,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "attester_key_id": signer.key_id,
    }
    body["sig"] = signer.sign(
        _ATTESTATION_DOMAIN + _canonical_json(body)).hex()
    return body


def _canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, default=str).encode("utf-8")


def verify_attestation(att, trusted_keys, expected_nonce=None,
                       max_age_s=None, now=None):
    """Verify attestation evidence. Returns (ok, error).

    Checks: well-formed envelope (version, flat str->str claims,
    non-empty nonce); ``attester_key_id`` in ``trusted_keys``
    ({key_id: 32-byte pubkey or hex}); Ed25519 signature over the
    canonical body. Freshness: when ``expected_nonce`` is given the
    attestation's nonce must equal it (challenge-response); when
    ``max_age_s`` is given, ``issued_at`` must be within that many
    seconds of ``now`` (defaults to current UTC). Passing NEITHER
    freshness input explicitly opts out of freshness checking --
    allowed, but the caller owns the replay risk (documented here so
    the opt-out is never accidental).
    """
    from . import ed25519 as _ed
    try:
        if not isinstance(att, dict):
            return False, "attestation is not an object"
        if att.get("attestation_version") != _ATTESTATION_VERSION:
            return False, "unsupported attestation_version"
        identity = att.get("identity")
        claims = att.get("claims")
        nonce = att.get("nonce")
        issued_at = att.get("issued_at")
        key_id = att.get("attester_key_id")
        sig_hex = att.get("sig")
        if not isinstance(identity, dict):
            return False, "identity missing"
        for field in ("agent_id", "role", "run_id", "principal"):
            if not isinstance(identity.get(field), str) \
                    or not identity[field]:
                return False, "identity field %r bad" % field
        if not isinstance(claims, dict) or not claims:
            return False, "claims missing or empty"
        for k, v in claims.items():
            if not isinstance(k, str) or not isinstance(v, str):
                return False, "claims not flat str->str"
        if not isinstance(nonce, str) or not nonce:
            return False, "nonce missing"
        pub = trusted_keys.get(key_id) if isinstance(
            trusted_keys, dict) else None
        if isinstance(pub, str):
            try:
                pub = bytes.fromhex(pub)
            except ValueError:
                pub = None
        if not isinstance(pub, (bytes, bytearray)) or len(pub) != 32:
            return False, "attester key %r not trusted" % (key_id,)
        try:
            sig = bytes.fromhex(sig_hex)
        except (TypeError, ValueError):
            return False, "malformed sig"
        body = {k: v for k, v in att.items() if k != "sig"}
        if not _ed.verify(bytes(pub),
                          _ATTESTATION_DOMAIN + _canonical_json(body),
                          sig):
            return False, "attestation signature invalid"
        if expected_nonce is not None and nonce != expected_nonce:
            return False, "nonce mismatch: replayed or wrong challenge"
        if max_age_s is not None:
            ref = now or datetime.now(timezone.utc)
            try:
                issued = datetime.fromisoformat(issued_at)
            except (TypeError, ValueError):
                return False, "issued_at not parseable"
            if issued.tzinfo is None:
                issued = issued.replace(tzinfo=timezone.utc)
            age = (ref - issued).total_seconds()
            if age < 0 or age > max_age_s:
                return False, "attestation not fresh (age %.1fs)" % age
        return True, None
    except (TypeError, ValueError, KeyError) as e:
        return False, "malformed attestation: %s" % (e,)
