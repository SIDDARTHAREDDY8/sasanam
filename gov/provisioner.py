"""Identity issuance policy: the provisioner abstraction + lifetime claims.

Steal: smallstep/certificates ``authority/provisioner`` (a typed
registry of attestation methods for minting short-lived credentials)
+ ``claims.go`` (the credential-lifetime policy envelope:
minTLSCertDuration / maxTLSCertDuration, disableRenewal,
allowRenewalAfterExpiry, layered global -> per-provisioner).

Steal ONLY the mechanism. smallstep gates TPM-attested enrollment,
active revocation (CRL/OCSP), and HSM-bound keys behind its commercial
product (per its own README); this module designs around none of them
and takes no dependency on smallstep -- stdlib only.

What this adds over the existing identity stack:

* ``PrincipalRegistry`` (gov/identity.py) answers WHO may mint --
  which (principal, role, agent_id) tuples a deployment recognizes.
* A ``Provisioner`` answers under WHAT CONSTRAINTS an issuance
  happens: which attestation method backs it, the minimum/maximum
  credential lifetime, the scopes and roles it may grant, whether the
  credential may be renewed, and how revocation is operated.
* ``ToolExecutor.mint_identity(..., provisioner=..., ttl_seconds=...,
  scopes=..., justification=...)`` routes issuance through the named
  provisioner when a ``ProvisionerRegistry`` is configured. The
  wave-191/192 token claim-set (``exp``, ``jti``) already carries
  expiry; the provisioner adds the *issuance policy* the token lane
  left out: a presented token whose lifetime exceeds the provisioner's
  max TTL is refused at mint time, and scopes the provisioner never
  granted are refused even when the token claims them.

Provisioner types mirror the step-ca vocabulary onto our seams:
``oidc`` = the dex-issued token work (wave-191/192) -- behaviorally,
an ``oidc`` provisioner *requires* the presented verified token
claim set (``requires_presented_token``), because the OIDC method
attests via the JWT and there is nothing to attest without it;
``jwk`` = our keyset-held keys (the keyset attestation itself is
checked at the existing ``find_verifying_key`` seam, which refuses
revoked keysets; the provisioner records ``revocation: keyset`` so
the operated mechanism is explicit on the chain);
``operator`` = the deployment-provisioned session identity (F55),
``workload`` = in-run agent workloads minted under a parent identity,
``break-glass`` = the loud, short-TTL, justification-gated emergency
path.

Layering notes (honest boundaries):

* The 5-field ``identity_token`` packet section (wave-192) is NOT
  extended -- legacy packets stay byte-identical. This is a deliberate
  deviation from a literal "packet path" reading of the requirement,
  for three reasons: (1) the claims are *enforced* at issuance
  (``mint_identity``), which happens before any decision packet
  exists -- the issuance record is their natural home; (2) threading
  mint-time envelopes into the per-decision packet builder would
  couple issuance policy to decision recording and risk the legacy
  byte-identical pins; (3) the chained audit log IS a signature layer
  in this system (hash chain + audit signing), and the
  ``identity_minted`` event now carries both the resolved outcome
  (ttl, scopes, expiry) and the authorizing envelope
  (``LifetimeClaims.as_audit_dict``), so the policy decision is
  reconstructible from the chain alone.
* Renewal: there is no renew API yet. The renewal *policy* is attached
  to every issuance (recorded as ``renewable`` / ``renew_after`` on
  the audit event) and ``Provisioner.renewal_allowed`` is the
  reference implementation of the step-ca claims semantics for the
  future renew path / the dex client.
* Revocation: ``LifetimeClaims.revocation`` declares the operated
  mechanism -- ``"expiry"`` (short TTLs; the default) or ``"keyset"``
  (the deployment revokes through keyset revocation, which
  ``find_verifying_key`` already refuses at the attestation seam).
  Active revocation beyond expiry + keyset revocation is a deployment
  runbook item, not code here -- the same honesty class as the F17b
  deployment-trust residual.
"""

__all__ = [
    "ProvisionerType",
    "LifetimeClaims",
    "Provisioner",
    "BreakGlassProvisioner",
    "ProvisionerRegistry",
    "ProvisionerRefusedError",
    "BreakGlassRefusedError",
    "UnknownProvisionerError",
]

import sys
import time
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Deployment warnings: loud, once per process. Unrestricted grants and the
# break-glass default envelope are deployment decisions that must never be
# silent (the same disclosure pattern as the dev-key warnings).
# ---------------------------------------------------------------------------

_warned_grants = set()


def _warn_grant_once(provisioner_name, topic, message):
    # One warning per (provisioner, topic) per process. The first
    # caller wins the wording, so the most specific check warns
    # first and the generic fallback stays silent.
    key = (provisioner_name, topic)
    if key in _warned_grants:
        return
    _warned_grants.add(key)
    print("GOVERNANCE WARNING: provisioner %r: %s"
          % (provisioner_name, message), file=sys.stderr)


# ---------------------------------------------------------------------------
# Exceptions: all refusals are loud and fail-closed.
# ---------------------------------------------------------------------------

class ProvisionerRefusedError(Exception):
    """An identity mint was refused by provisioner issuance policy.

    Fail-closed: a refused mint never consumes issuance budget and
    never issues. Audited as ``identity_mint_refused`` with
    ``policy_id`` ``provisioner:<name>``.
    """


class BreakGlassRefusedError(ProvisionerRefusedError):
    """A break-glass mint was refused (no justification, TTL too long,
    or the break-glass claims envelope). Distinct subclass so callers
    -- and auditors -- can tell an emergency-path refusal apart from
    an ordinary policy refusal."""


class UnknownProvisionerError(ProvisionerRefusedError):
    """The named provisioner is not in the deployment's registry."""


# ---------------------------------------------------------------------------
# Provisioner types: the step-ca attestation-method vocabulary, mapped
# onto our seams.
# ---------------------------------------------------------------------------

class ProvisionerType:
    """Attestation-method types a provisioner may embody.

    OIDC: the dex-issued identity token (wave-191/192 claim-set).
    JWK: a keyset-held key attesting the workload.
    OPERATOR: the deployment-provisioned session identity (F55).
    WORKLOAD: in-run agent workloads minted under a parent identity.
    BREAK_GLASS: the emergency path -- loud, short-TTL, gated on an
    explicit justification (see BreakGlassProvisioner).
    """
    OIDC = "oidc"
    JWK = "jwk"
    OPERATOR = "operator"
    WORKLOAD = "workload"
    BREAK_GLASS = "break-glass"

    ALL = frozenset({OIDC, JWK, OPERATOR, WORKLOAD, BREAK_GLASS})


# The deployment-wide default requested lifetime (seconds) when the
# caller does not ask for one; always capped by the provisioner's
# max_ttl_seconds (the step-ca global -> per-provisioner layering).
DEFAULT_TTL_SECONDS = 3600

# Revocation mechanisms a deployment may declare per provisioner.
REVOCATION_MODES = frozenset({"expiry", "keyset"})


def _clean_str_set(values, what, owner):
    if values is None:
        return None
    if isinstance(values, str):
        values = [values]
    try:
        items = list(values)
    except TypeError:
        raise ValueError(
            "%s for %r must be a collection of non-empty strings" %
            (what, owner))
    if not items:
        raise ValueError(
            "%s for %r must not be empty (use None for unrestricted)" %
            (what, owner))
    out = set()
    for v in items:
        if not isinstance(v, str) or not v.strip():
            raise ValueError(
                "%s for %r must be non-empty strings, got %r" %
                (what, owner, v))
        out.add(v.strip())
    return frozenset(out)


def _clean_int(value, what, owner, minimum=None, allow_none=False):
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            "%s for %r must be an int, got %r" % (what, owner, value))
    if minimum is not None and value < minimum:
        raise ValueError(
            "%s for %r must be >= %d, got %d" %
            (what, owner, minimum, value))
    return value


@dataclass(frozen=True)
class LifetimeClaims:
    """The per-issuer credential-lifetime policy envelope (step-ca
    ``claims.go``, adapted).

    max_ttl_seconds: hard ceiling on credential lifetime. A presented
    token whose (exp - iat) exceeds this is refused at mint time.
    min_ttl_seconds: floor; absurdly short lifetimes are refused.
    disable_renewal: the credential may not be renewed (break-glass
    default).
    allow_renewal_after_expiry: renewal is permitted after expiry
    (default False -- an expired credential stays expired).
    renewal_window_seconds: renewals are only allowed this many
    seconds before expiry (None = any time while live).
    allowed_scopes: scopes this provisioner may grant (None =
    unrestricted; prefer explicit).
    allowed_roles: roles this provisioner may mint (None = defer to
    the PrincipalRegistry).
    max_mints_per_run: per-provisioner issuance budget (None = the
    executor-wide budget only).
    revocation: the operated revocation mechanism, "expiry" or
    "keyset" (see module docstring).
    """
    max_ttl_seconds: int
    min_ttl_seconds: int = 0
    disable_renewal: bool = False
    allow_renewal_after_expiry: bool = False
    renewal_window_seconds: int = None
    allowed_scopes: frozenset = None
    allowed_roles: frozenset = None
    max_mints_per_run: int = None
    revocation: str = "expiry"

    def __post_init__(self):
        name = "LifetimeClaims"
        max_ttl = _clean_int(self.max_ttl_seconds, "max_ttl_seconds",
                             name, minimum=1)
        min_ttl = _clean_int(self.min_ttl_seconds, "min_ttl_seconds",
                             name, minimum=0)
        if min_ttl > max_ttl:
            raise ValueError(
                "min_ttl_seconds (%d) > max_ttl_seconds (%d)" %
                (min_ttl, max_ttl))
        _clean_int(self.renewal_window_seconds, "renewal_window_seconds",
                   name, minimum=0, allow_none=True)
        _clean_int(self.max_mints_per_run, "max_mints_per_run", name,
                   minimum=1, allow_none=True)
        if not isinstance(self.disable_renewal, bool):
            raise ValueError("disable_renewal must be a bool")
        if not isinstance(self.allow_renewal_after_expiry, bool):
            raise ValueError("allow_renewal_after_expiry must be a bool")
        if self.revocation not in REVOCATION_MODES:
            raise ValueError(
                "revocation must be one of %s, got %r" %
                (sorted(REVOCATION_MODES), self.revocation))
        # Normalize the scope/role collections to frozensets (frozen
        # dataclass: use object.__setattr__).
        object.__setattr__(self, "allowed_scopes",
                           _clean_str_set(self.allowed_scopes,
                                          "allowed_scopes", name))
        object.__setattr__(self, "allowed_roles",
                           _clean_str_set(self.allowed_roles,
                                          "allowed_roles", name))

    def as_audit_dict(self):
        """The envelope as a JSON-able dict for the chained audit event.

        The ``identity_minted`` event records the resolved outcome
        (ttl, scopes); this records the envelope that authorized it,
        so an auditor can reconstruct the policy check from the chain
        alone -- the deployment config stays off-chain, the decision
        does not.
        """
        return {
            "max_ttl_seconds": self.max_ttl_seconds,
            "min_ttl_seconds": self.min_ttl_seconds,
            "disable_renewal": self.disable_renewal,
            "allow_renewal_after_expiry":
                self.allow_renewal_after_expiry,
            "renewal_window_seconds": self.renewal_window_seconds,
            "allowed_scopes": (sorted(self.allowed_scopes)
                               if self.allowed_scopes is not None
                               else None),
            "allowed_roles": (sorted(self.allowed_roles)
                              if self.allowed_roles is not None
                              else None),
            "max_mints_per_run": self.max_mints_per_run,
            "revocation": self.revocation,
        }

    def default_ttl(self):
        """The TTL used when the caller requests none: the
        deployment-wide default capped by this envelope's max."""
        return min(DEFAULT_TTL_SECONDS, self.max_ttl_seconds)


class Provisioner:
    """One issuance authority: an attestation method + its lifetime
    claims envelope.

    ``name`` is the deployment-scoped instance id (e.g. "dex-prod").
    ``provisioner_type`` is one of ``ProvisionerType.ALL``. ``claims``
    is the ``LifetimeClaims`` envelope enforced on every mint through
    this provisioner.
    """

    def __init__(self, name, provisioner_type, claims):
        if not isinstance(name, str) or not name.strip():
            raise ValueError("provisioner name must be a non-empty "
                             "string, got %r" % (name,))
        if provisioner_type not in ProvisionerType.ALL:
            raise ValueError(
                "provisioner type must be one of %s, got %r" %
                (sorted(ProvisionerType.ALL), provisioner_type))
        if not isinstance(claims, LifetimeClaims):
            raise TypeError("provisioner claims must be LifetimeClaims, "
                            "got %r" % (claims,))
        self.name = name.strip()
        self.provisioner_type = provisioner_type
        self.claims = claims
        if claims.allowed_scopes is None:
            # Unrestricted scope grants are a deployment decision that
            # must never be silent: None means "every scope", and a
            # missing frozenset() is indistinguishable from intent at
            # the type level. (allowed_roles=None is the normal "defer
            # to the PrincipalRegistry" config and is not warned on.)
            _warn_grant_once(
                self.name,
                "unrestricted-scopes",
                "grants UNRESTRICTED scopes (allowed_scopes=None). "
                "Pass an explicit scope set to narrow it.")

    def __repr__(self):
        return "Provisioner(%r, %r)" % (self.name, self.provisioner_type)

    def requires_presented_token(self):
        """Whether this attestation method needs a presented token.

        The OIDC method attests via the dex-issued JWT (the wave-191
        verified claim set): with no presented token there is nothing
        attesting the identity, so the executor refuses the mint
        fail-closed. The other methods attest another way (a
        keyset-held key, the deployment session, the parent workload,
        the break-glass justification) and do not require one. This is
        what makes the ``oidc`` type a real mapping onto the dex token
        seam rather than a label.
        """
        return self.provisioner_type == ProvisionerType.OIDC

    # -- issuance policy ------------------------------------------------

    def authorize_mint(self, ttl_seconds, scopes, justification, role):
        """Check a mint request against this provisioner's envelope.

        ``ttl_seconds``: requested lifetime (int). ``scopes``: iterable
        of requested scope strings (may be empty). ``justification``:
        ignored by the base provisioner (only the break-glass type
        gates on it) -- documented so the ignore is never accidental.
        ``role``: the requested role string.

        Returns ``(True, "ok")`` or ``(False, reason)``; never raises
        on policy grounds (constructor-time validation raises
        instead). The caller (``ToolExecutor.mint_identity``) turns a
        refusal into ``ProvisionerRefusedError``.
        """
        c = self.claims
        if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds,
                                                            int):
            return False, ("provisioner %r: ttl_seconds must be an int, "
                           "got %r" % (self.name, ttl_seconds))
        if ttl_seconds < c.min_ttl_seconds:
            return False, ("provisioner %r: ttl_seconds %d below "
                           "min_ttl_seconds %d" %
                           (self.name, ttl_seconds, c.min_ttl_seconds))
        if ttl_seconds > c.max_ttl_seconds:
            return False, ("provisioner %r: ttl_seconds %d exceeds "
                           "max_ttl_seconds %d" %
                           (self.name, ttl_seconds, c.max_ttl_seconds))
        scope_list = list(scopes or ())
        for s in scope_list:
            if not isinstance(s, str) or not s.strip():
                return False, ("provisioner %r: scopes must be "
                               "non-empty strings, got %r" %
                               (self.name, s))
        if c.allowed_scopes is not None:
            outside = [s for s in scope_list if s not in c.allowed_scopes]
            if outside:
                return False, ("provisioner %r: scope(s) %s outside the "
                               "provisioner's grant %s" %
                               (self.name, sorted(outside),
                                sorted(c.allowed_scopes)))
            if not scope_list:
                # A scoped grant with no requested scopes mints an
                # empty-scoped identity that evades the grant list --
                # refuse rather than mint a scope the grant never
                # names. (Unrestricted grants, allowed_scopes=None,
                # still accept empty scope lists.)
                return False, ("provisioner %r: no scopes requested, "
                               "but the provisioner grants %s -- "
                               "request at least one scope" %
                               (self.name, sorted(c.allowed_scopes)))
        if c.allowed_roles is not None and role not in c.allowed_roles:
            return False, ("provisioner %r: role %r outside the "
                           "provisioner's grant %s" %
                           (self.name, role, sorted(c.allowed_roles)))
        return True, "ok"

    # -- renewal policy (reference implementation) -----------------------

    def renewal_allowed(self, issued_at_epoch, expires_at_epoch,
                        now_epoch=None):
        """The step-ca claims renewal semantics, as a pure function.

        No renew API exists yet; this is the reference implementation
        for the future renew path / the dex client, and it is what the
        ``renewable`` / ``renew_after`` fields recorded on the
        ``identity_minted`` audit event mean.

        Returns ``(True, "ok")`` or ``(False, reason)``.
        """
        c = self.claims
        now = time.time() if now_epoch is None else now_epoch
        for label, v in (("issued_at", issued_at_epoch),
                         ("expires_at", expires_at_epoch),
                         ("now", now)):
            if isinstance(v, bool) or not isinstance(v, (int, float)):
                return False, "renewal check: %s is not a number" % label
        if issued_at_epoch > expires_at_epoch:
            return False, "renewal check: issued_at after expires_at"
        if c.disable_renewal:
            return False, ("renewal disabled by provisioner %r policy" %
                           self.name)
        if now > expires_at_epoch and not c.allow_renewal_after_expiry:
            return False, ("credential expired and provisioner %r does "
                           "not allow renewal after expiry" % self.name)
        if (c.renewal_window_seconds is not None
                and now < expires_at_epoch - c.renewal_window_seconds):
            return False, ("renewal window for provisioner %r opens at "
                           "%.0f (%.0fs before expiry)" %
                           (self.name,
                            expires_at_epoch - c.renewal_window_seconds,
                            c.renewal_window_seconds))
        return True, "ok"


class BreakGlassProvisioner(Provisioner):
    """The emergency issuance path: loud, short-TTL, justification-gated.

    Defaults: 5-minute max TTL, renewal disabled, no renewal after
    expiry. Every mint requires a non-empty justification string;
    without one the mint is refused fail-closed
    (``BreakGlassRefusedError``). Successful break-glass mints are
    audit-logged twice: the standard ``identity_minted`` event (with
    ``renewable: false``) and a dedicated
    ``identity_break_glass_minted`` event carrying the justification,
    plus a loud stderr warning at mint time.
    """

    DEFAULT_BREAK_GLASS_TTL = 300

    def __init__(self, name, claims=None,
                 max_ttl_seconds=DEFAULT_BREAK_GLASS_TTL):
        _defaulted = claims is None
        if _defaulted:
            claims = LifetimeClaims(
                max_ttl_seconds=max_ttl_seconds,
                disable_renewal=True,
                allow_renewal_after_expiry=False)
        super().__init__(name, ProvisionerType.BREAK_GLASS, claims)
        if _defaulted:
            # The emergency path defaults to UNRESTRICTED scopes and
            # roles (in a real break-glass there is no grant list left
            # standing) -- that breadth must be a loud deployment
            # decision, never a quiet default. Pass explicit claims to
            # narrow it.
            _warn_grant_once(
                self.name,
                "break-glass-default-envelope",
                "break-glass emergency path uses the default envelope: "
                "UNRESTRICTED scopes and roles, gated ONLY by the "
                "justification. Pass explicit claims to narrow it, and "
                "review every identity_break_glass_minted event.")

    def authorize_mint(self, ttl_seconds, scopes, justification, role):
        """Break-glass gate: a non-empty justification is required.

        Delegates the remaining envelope checks (TTL, scopes, roles)
        to :meth:`Provisioner.authorize_mint`.
        """
        if not isinstance(justification, str) or not justification.strip():
            return False, ("break-glass mint by provisioner %r refused: "
                           "an explicit justification is required" %
                           self.name)
        return super().authorize_mint(ttl_seconds, scopes, justification,
                                      role)


class ProvisionerRegistry:
    """The deployment's issuance authorities: name -> Provisioner.

    The step-ca ``authority/provisioner`` package is a typed registry
    of attestation methods; this is the same shape for agent identity.
    Constructed from deployment configuration, never from agent input.
    Accepts a ``{name: Provisioner}`` dict or an iterable of
    ``Provisioner`` (keyed by ``.name``).
    """

    def __init__(self, provisioners):
        if isinstance(provisioners, dict):
            items = list(provisioners.items())
        else:
            try:
                items = [(p.name, p) for p in provisioners]
            except TypeError:
                raise ValueError(
                    "ProvisionerRegistry needs a {name: Provisioner} "
                    "dict or an iterable of Provisioner")
        if not items:
            raise ValueError("ProvisionerRegistry needs at least one "
                             "provisioner")
        seen = {}
        for name, p in items:
            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    "provisioner names must be non-empty strings, got "
                    "%r" % (name,))
            if not isinstance(p, Provisioner):
                raise ValueError(
                    "provisioner %r must be a Provisioner, got %r" %
                    (name, p))
            if p.name != name.strip():
                raise ValueError(
                    "registry key %r does not match provisioner name %r" %
                    (name, p.name))
            if name.strip() in seen:
                raise ValueError("duplicate provisioner name %r" % (name,))
            seen[name.strip()] = p
        self._provisioners = seen

    def get(self, name):
        """Return the named provisioner, or raise
        ``UnknownProvisionerError`` (a ``ProvisionerRefusedError``)."""
        try:
            return self._provisioners[name]
        except (KeyError, TypeError):
            raise UnknownProvisionerError(
                "unknown provisioner %r (registered: %s); issuance "
                "refused" % (name, sorted(self._provisioners)))

    def names(self):
        """The registered provisioner names (for audit/debugging)."""
        return sorted(self._provisioners)

    def __len__(self):
        return len(self._provisioners)

    def __contains__(self, name):
        return name in self._provisioners
