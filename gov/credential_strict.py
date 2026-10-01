"""Credential never-materialize (strict) tier: supervisor-owned egress.

ADAPTED PATTERN — credit: ``nvidia/openshell``
(``docs/how-it-works/providers/``, Apache-2.0). Their model: agents
never see real credentials; the supervisor injects credentials into
requests bound for approved endpoints only (exemplar: AWS SigV4 — the
proxy strips the sandbox client's placeholder ``Authorization`` header
and re-signs with real provider credentials; "the sandbox never sees
the real credentials"). Pattern only: no OpenShell code or text
vendored.

Our default tier is sentinel placeholders (``fake_value_<uuid>``) that
the executor swaps at the execution boundary
(``gov/sentinel_substitution.py``). This module adds the STRICT tier
above it for the highest-sensitivity credentials:

* A strict credential's real value is NEVER resolved inside the
  agent-visible execution environment. ``substitute_for_execution``
  refuses any strict sentinel with ``credential-strict-refused``
  (the single agent-side resolution choke point — both the direct
  and the approved-sweep executor paths go through it).
* Resolution happens ONLY in :class:`StrictEgressInjector`, the
  supervisor-owned egress path, where the request must be (a)
  already approved (a deployment-supplied approval check bound to
  tool + destination), (b) destined for a host in the credential's
  ``inject_hosts``, and (c) injected at the protocol layer via a
  deployment-supplied ``transport`` callable (the L7 re-sign analog:
  the transport performs the actual network send after injection).
* Strict credentials are bound to ONE named injector instance
  (``strict_injector`` operator label); a different injector
  instance refuses them. Malformed strict config fails closed at
  registration (``credential-strict-config-invalid``) — nothing is
  registered.

The agent receives only a digest receipt
(``injected_digest`` = sha256 over the canonical injected args);
``transport``'s return value is passed through opaquely. Real values
never enter the audit log, the vault repr, or any agent-visible
structure — the injector's audit events carry credential ids,
destination hosts, and sentinel prefixes only.

Honest boundaries (prototype)
-----------------------------
- The supervisor egress path is deployment-owned: the deployment
  supplies ``check_approval`` and ``transport``. This module
  enforces the gating; it cannot vouch for what the deployment's
  transport does with the injected request (e.g. a transport that
  echoes secrets upstream would defeat the tier — deployments must
  treat the transport as part of their trusted computing base).
- ``transport``'s return value is passed through to the agent
  opaquely; a deployment whose upstream echoes credential material
  in responses must scrub at its own seam.
- Strict mode does not cover semantic paraphrase exfiltration (an
  agent retyping a secret it was told in-band is outside any
  substitution tier's reach); that stays a known residual.
- Strict credentials still pass the attempt-path binding and
  attestation pre-checks unchanged (args stay sentinel-bearing
  there); only the resolution seam refuses.
- Attestation release (wave-198) is the agent-side release
  predicate; on the strict supervisor path the deployment's
  approval check replaces it. Deployments that need both can
  thread attestation evaluation into their ``check_approval``.

$0, stdlib only, no network calls. Deterministic given the vault.
"""

import hashlib
import json

try:
    from .sentinel_substitution import (
        SentinelError,
        SentinelVault,
        extract_dest_host,
        find_sentinels,
        substitute_in,
    )
except ImportError:  # pragma: no cover - direct module use
    from sentinel_substitution import (
        SentinelError,
        SentinelVault,
        extract_dest_host,
        find_sentinels,
        substitute_in,
    )

__all__ = [
    "CredentialStrictError",
    "StrictEgressInjector",
    "is_strict_sentinel",
]

# Machine codes (gov/decision_codes.py, domain 'credential').
CODE_CONFIG_INVALID = "credential-strict-config-invalid"
CODE_HOST_DENIED = "credential-strict-host-denied"
CODE_REFUSED = "credential-strict-refused"
CODE_UNAPPROVED = "credential-strict-unapproved"


class CredentialStrictError(SentinelError):
    """Fail-closed refusal of the strict credential tier.

    Carries the taxonomy ``code``; the message is machine-coded
    (starts with the code) so callers can match without parsing
    prose. Subclasses :class:`SentinelError` so existing
    ``except SentinelError`` handlers keep failing closed.
    """

    def __init__(self, code, detail=""):
        self.code = code
        super(CredentialStrictError, self).__init__(
            "%s: %s" % (code, detail) if detail else code)


def is_strict_sentinel(vault, token):
    """True iff ``token`` is a registered never-materialize sentinel."""
    if vault is None or not isinstance(token, str):
        return False
    rec = vault.lookup(token)
    return rec is not None and bool(rec.get("strict"))


def _canonical_digest(mapping):
    body = json.dumps(mapping, sort_keys=True, default=str,
                      separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _sentinel_prefix(token):
    """Attribution-safe token prefix for audit events (never a value)."""
    return token[:20] + "..."


class StrictEgressInjector(object):
    """Supervisor-owned egress path for never-materialize credentials.

    Constructed ONCE per supervisor egress seam by the deployment::

        inj = StrictEgressInjector(
            vault, "egress-prod",
            check_approval=my_approval_check,  # (approval, tool,
                                              #  dest_host) -> bool
            transport=my_l7_send,              # (tool, injected_args,
                                              #  context) -> result
            audit=audit_list)                  # optional; no secrets

    ``inject(tool, args, approval=..., context=...)`` then:

    1. every sentinel in ``args`` must be a known strict credential
       (else ``credential-strict-refused`` — this injector handles
       never-materialize credentials only);
    2. every credential must be bound to THIS injector's ``name``
       (else ``credential-strict-refused``);
    3. ``check_approval(approval, tool, dest_host)`` must be truthy
       (else ``credential-strict-unapproved`` — a raising check
       denies too);
    4. ``dest_host`` must be in every credential's ``inject_hosts``
       (else ``credential-strict-host-denied``);
    5. values are substituted into an EPHEMERAL copy and handed to
       ``transport``; the agent receives a digest receipt only.

    Construction with a non-SentinelVault vault, an empty name, or a
    non-callable check/transport refuses immediately
    (``credential-strict-config-invalid``) — an injector without its
    trust anchors must not exist.
    """

    def __init__(self, vault, name, check_approval, transport,
                 audit=None):
        if not isinstance(vault, SentinelVault):
            raise CredentialStrictError(
                CODE_CONFIG_INVALID,
                "vault must be a gov.sentinel_substitution."
                "SentinelVault")
        if not isinstance(name, str) or not name.strip():
            raise CredentialStrictError(
                CODE_CONFIG_INVALID,
                "injector name must be a non-empty operator label")
        if not callable(check_approval):
            raise CredentialStrictError(
                CODE_CONFIG_INVALID,
                "check_approval must be callable "
                "(approval, tool, dest_host) -> bool")
        if not callable(transport):
            raise CredentialStrictError(
                CODE_CONFIG_INVALID,
                "transport must be callable "
                "(tool, injected_args, context) -> result")
        if audit is not None and not hasattr(audit, "append"):
            raise CredentialStrictError(
                CODE_CONFIG_INVALID,
                "audit must be None or an appendable list")
        self._vault = vault
        self._name = name.strip()
        self._check_approval = check_approval
        self._transport = transport
        self._audit = audit

    @property
    def name(self):
        return self._name

    def _log(self, event):
        if self._audit is not None:
            try:
                self._audit.append(event)
            except Exception:
                pass  # audit is best-effort; the refusal is not

    def _refuse(self, code, detail, fields):
        event = {"event": "credential_strict_refused",
                 "code": code,
                 "injector": self._name}
        event.update(fields)
        self._log(event)
        raise CredentialStrictError(code, detail)

    def inject(self, tool, args, approval=None, context=None):
        """Inject strict credentials at the supervisor egress seam."""
        tokens = list(find_sentinels(args))
        if not tokens:
            self._refuse(
                CODE_REFUSED,
                "no credential sentinel in args: nothing to inject",
                {"tool": tool})
        recs = []
        for tok in tokens:
            rec = self._vault.lookup(tok)
            if rec is None or not rec.get("strict"):
                self._refuse(
                    CODE_REFUSED,
                    "sentinel is not a registered never-materialize "
                    "credential: the strict injector handles strict "
                    "credentials only",
                    {"tool": tool,
                     "sentinel_prefix": _sentinel_prefix(tok)})
            if rec.get("strict_injector") != self._name:
                self._refuse(
                    CODE_REFUSED,
                    "credential %r is bound to strict injector %r, "
                    "not %r" % (rec["credential_id"],
                                rec.get("strict_injector"),
                                self._name),
                    {"tool": tool,
                     "credential_id": rec["credential_id"]})
            recs.append((tok, rec))
        dest = extract_dest_host(tool, args)
        try:
            approved = self._check_approval(approval, tool, dest)
        except Exception:
            approved = False  # a raising check denies: fail closed
        if not approved:
            self._refuse(
                CODE_UNAPPROVED,
                "supervisor egress injection refused: the request "
                "has no valid approval for tool %r at %r"
                % (tool, dest),
                {"tool": tool, "dest_host": dest,
                 "credential_ids": [r["credential_id"]
                                    for _, r in recs]})
        for tok, rec in recs:
            if dest is None or dest not in rec["hosts"]:
                self._refuse(
                    CODE_HOST_DENIED,
                    "supervisor egress injection refused: credential "
                    "%r is not bound to destination %r"
                    % (rec["credential_id"], dest),
                    {"tool": tool, "dest_host": dest,
                     "credential_id": rec["credential_id"]})
        cids = [rec["credential_id"] for _, rec in recs]
        mapping = {tok: rec["real"] for tok, rec in recs}
        injected = substitute_in(args, mapping)
        digest = _canonical_digest(injected)
        ctx = {"dest_host": dest, "credential_ids": list(cids),
               "injector": self._name}
        if isinstance(context, dict):
            ctx.update(context)
        result = self._transport(tool, injected, ctx)
        self._log({"event": "credential_strict_injected",
                   "injector": self._name,
                   "tool": tool,
                   "dest_host": dest,
                   "credential_ids": cids,
                   "injected_digest": digest,
                   "sentinel_prefixes": [_sentinel_prefix(tok)
                                         for tok, _ in recs]})
        return {"credential_ids": cids,
                "dest_host": dest,
                "injected_digest": digest,
                "transport_result": result}
