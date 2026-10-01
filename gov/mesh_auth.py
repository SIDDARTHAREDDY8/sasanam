"""Agent-mesh auth contract: A2A-style auth declarations, per-request
auth envelopes, and mid-task escalation (wave-263 lane 2).

An A2A ADAPT of the *protocol shapes* only (no A2A code or spec text
is read, copied, imported, or vendored):

* **SecurityScheme declarations on agent cards** (A2A §4.5). Every
  mesh member's :class:`MeshAuthCard` declares which authentication
  schemes it accepts. A2A's scheme vocabulary is mapped onto OUR
  credential primitives — no new crypto is invented:

  ==================  =================================  ============
  A2A scheme          our primitive                      seam
  ==================  =================================  ============
  MutualTlsSecurity   ``svid``                           mutual
  Scheme                                           identity, verified
                                                   first via
                                                   gov.svid_issuer.
                                                   MeshControl
  OAuth2Security      ``scope-ticket``                   scoped MAC-
  Scheme                                           bound grant from
                                                   gov.scoped_tool_
                                                   listing.
                                                   ScopeTicketIssuer
  APIKeySecurity /    ``short-lived-credential``         bearer
  HTTPAuthSecurity                                     (credential_id,
  Scheme                                           secret) verified
                                                   by gov.short_lived
                                                   _credentials.
                                                   CredentialIssuer
  OpenIdConnectSecurityScheme  — none —                 refused at
                                                   declaration time
                                                   (mesh-auth-
                                                   malformed): we
                                                   have no OIDC
                                                   primitive and do
                                                   not fake one.
  ==================  =================================  ============

* **Per-request authentication** (A2A §7.3/§7.4). Every mesh call
  carries an auth envelope ``{"scheme": ..., "credential": ...}``
  that :class:`MeshCallGate` verifies BEFORE routing. Admission
  (``gov.mesh_admission.MeshAdmission``) decides the *route*; this
  gate decides *per-call auth*. Undeclared scheme -> refused;
  missing/tampered envelope -> refused; a credential presented under
  the wrong scheme (identity where a scope grant is required) ->
  ``mesh-auth-scheme-confusion`` refused (schemes are never silently
  substituted for each other).

* **Authorization dimensions** (A2A §7.5). Each authorized call
  records who (verified subject), what (callee member), scope (the
  credential's scopes vs the required scopes — exact-set, the
  scope-listing discipline), and context (the evaluated clock).
  Scope coverage is evaluated at the call seam.

* **Mid-task escalation** (A2A §7.6). :class:`MeshTaskAuth` is the
  task state machine. When a task mid-flight needs stronger auth
  than it started with, ``escalate()`` transitions it to the
  machine-coded ``AUTH_REQUIRED`` state with a record of what is
  needed; the task PAUSES. The escalation is fulfilled out-of-band
  (the credential never transits the task's own channel — the same
  discipline as our sentinel substitution); ``resume()`` re-runs
  the gate requiring the escalated scheme. Ignored escalation ->
  the task stays paused and every further call refuses
  ``mesh-auth-task-paused``; presenting the old/weaker scheme at
  resume -> ``mesh-auth-escalation-bypass``. A paused task never
  proceeds and never fails silently.

* **Tiered card disclosure** (A2A §6.9). ``public_view()`` shows
  capabilities + the declared scheme names (capability discovery
  *includes* the auth contract); ``authenticated_view()`` adds the
  connection endpoints. Servers only hand the authenticated view to
  verified callers.

Composition (never duplication):

* SVID path: ``gov.svid_issuer.MeshControl.admit`` (verify-first,
  default-deny ACL). Its ``svid-*`` refusals propagate unchanged.
* Scope-ticket path: ``gov.scoped_tool_listing.ScopeTicketIssuer``
  (MAC-bound, subject-bound, universe-checked). Its
  ``scope-grant-tampered`` / ``scope-listing-*`` refusals propagate
  unchanged.
* Short-lived-credential path:
  ``gov.short_lived_credentials.CredentialIssuer``. Its
  ``short-lived-credential-*`` refusals propagate unchanged.
* This module's own machine codes are ``mesh-auth-*`` (contract
  decisions only: undeclared scheme, missing envelope, scheme
  confusion, scope uncovered, subject mismatch, task paused,
  escalation bypass, malformed).

Fail-closed: every refusal is machine-coded; nothing proceeds on a
partial verification. Key distribution (who holds the ticket /
credential / SVID keys) is deployment-owned.

Honest boundaries
-----------------
* This is an auth CONTRACT between cooperating mesh members. It does
  not solve Sybil (a deployment can issue SVIDs to attacker-run
  agents) or first-contact trust (trust roots, issuer keys, and ACLs
  are pinned deployment material).
* A standalone scope-ticket presentation proves bearer capability,
  not subject identity: the ticket's ``sub`` is a digest the
  presenter cannot prove ownership of without a paired SVID.
  Deployments needing subject binding pass ``subject=`` (the
  verified spiffe_id); mismatch refuses ``mesh-auth-subject-
  mismatch``.
* Transport security (A2A §7.1's TLS 1.3 MUST) is assumed from the
  deployment, as is the clock the verifiers run on (injectable
  ``now``; a None ``now`` resolves to ``time.time()``).

Stdlib only. Deterministic: injectable clock (``now`` args), no I/O,
no network, no in-repo git subprocesses.
"""

import hashlib
import hmac
import os
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# ---------------------------------------------------------------------------
# Scheme vocabulary: our primitives + the A2A aliases that resolve to them.
# ---------------------------------------------------------------------------

SCHEME_SVID = "svid"
SCHEME_SHORT_LIVED_CREDENTIAL = "short-lived-credential"
SCHEME_SCOPE_TICKET = "scope-ticket"

OUR_SCHEMES = frozenset([
    SCHEME_SVID,
    SCHEME_SHORT_LIVED_CREDENTIAL,
    SCHEME_SCOPE_TICKET,
])

#: A2A SecurityScheme vocabulary -> our primitives. "oidc" (A2A
#: OpenIdConnectSecurityScheme) is deliberately ABSENT: we have no
#: OIDC primitive, and declaring it refuses mesh-auth-malformed
#: rather than pretending support.
A2A_ALIASES = {
    "mTLS": SCHEME_SVID,            # A2A MutualTlsSecurityScheme
    "mutual-tls": SCHEME_SVID,
    "oauth2": SCHEME_SCOPE_TICKET,  # A2A OAuth2SecurityScheme
    "apiKey": SCHEME_SHORT_LIVED_CREDENTIAL,  # A2A APIKeySecurityScheme
    "http": SCHEME_SHORT_LIVED_CREDENTIAL,    # A2A HTTPAuthSecurityScheme
}

# ---------------------------------------------------------------------------
# Machine codes (registered in gov/decision_codes.py, domain "mesh-auth").
# ---------------------------------------------------------------------------

MALFORMED_CODE = "mesh-auth-malformed"
ENVELOPE_MISSING_CODE = "mesh-auth-envelope-missing"
UNDECLARED_SCHEME_CODE = "mesh-auth-undeclared-scheme"
SCHEME_CONFUSION_CODE = "mesh-auth-scheme-confusion"
SCOPE_UNCOVERED_CODE = "mesh-auth-scope-uncovered"
SUBJECT_MISMATCH_CODE = "mesh-auth-subject-mismatch"
TASK_PAUSED_CODE = "mesh-auth-task-paused"
ESCALATION_BYPASS_CODE = "mesh-auth-escalation-bypass"

CODES = (
    MALFORMED_CODE,
    ENVELOPE_MISSING_CODE,
    UNDECLARED_SCHEME_CODE,
    SCHEME_CONFUSION_CODE,
    SCOPE_UNCOVERED_CODE,
    SUBJECT_MISMATCH_CODE,
    TASK_PAUSED_CODE,
    ESCALATION_BYPASS_CODE,
)

# ---------------------------------------------------------------------------
# Task states (machine-coded).
# ---------------------------------------------------------------------------

TASK_STATE_ACTIVE = "active"
TASK_STATE_AUTH_REQUIRED = "auth-required"
TASK_STATE_ABANDONED = "abandoned"

__all__ = [
    "MeshAuthError",
    "MeshAuthCard",
    "MeshCallGate",
    "MeshTaskAuth",
    "A2A_ALIASES",
    "CODES",
    "OUR_SCHEMES",
    "SCHEME_SVID",
    "SCHEME_SHORT_LIVED_CREDENTIAL",
    "SCHEME_SCOPE_TICKET",
    "TASK_STATE_ACTIVE",
    "TASK_STATE_AUTH_REQUIRED",
    "TASK_STATE_ABANDONED",
]


class MeshAuthError(Exception):
    """Machine-coded refusal. ``code`` is a decision-code taxonomy key."""

    def __init__(self, code, detail=""):
        super(MeshAuthError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _validate_now(now):
    """The repo-wide clock contract (F228 shape): a None ``now``
    resolves to ``time.time()``; a non-finite/bool/non-numeric ``now``
    refuses machine-coded before ANY refusal decision."""
    if now is None:
        return float(time.time())
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise MeshAuthError(
            MALFORMED_CODE, "now must be a finite number or None")
    if now != now or now in (float("inf"), float("-inf")):
        raise MeshAuthError(
            MALFORMED_CODE, "now must be finite (got NaN/inf)")
    return float(now)


def _resolve_scheme(name):
    """Resolve one declared scheme entry to our primitive.

    Accepts our primitive names and the A2A aliases. Unknown names
    (including "oidc", which we have no primitive for) refuse
    mesh-auth-malformed at DECLARATION time: a card can never
    advertise a scheme the member cannot actually verify.
    """
    if not isinstance(name, str) or not name:
        raise MeshAuthError(
            MALFORMED_CODE, "scheme entries must be non-empty strings")
    if name in OUR_SCHEMES:
        return name
    resolved = A2A_ALIASES.get(name)
    if resolved is not None:
        return resolved
    raise MeshAuthError(
        MALFORMED_CODE,
        "scheme %r is not one of our primitives %s and has no A2A "
        "alias (note: 'oidc' is unsupported — we have no OIDC "
        "primitive)" % (name, sorted(OUR_SCHEMES)))


class MeshAuthCard(object):
    """A mesh member's declared auth contract (A2A §4.5 shape).

    ``security_schemes``: the schemes this member accepts — our
    primitive names and/or A2A aliases (resolved at declaration; a
    member may declare the empty set, in which case EVERY call
    refuses ``mesh-auth-undeclared-scheme``). ``endpoints`` and
    ``capabilities`` are deployment-owned card content.
    """

    def __init__(self, member_id, security_schemes, endpoints=None,
                 capabilities=None):
        if not isinstance(member_id, str) or not member_id:
            raise MeshAuthError(
                MALFORMED_CODE, "member_id must be a non-empty string")
        if not isinstance(security_schemes, (list, tuple)):
            raise MeshAuthError(
                MALFORMED_CODE, "security_schemes must be a list/tuple")
        self._member_id = member_id
        self._schemes = frozenset(
            _resolve_scheme(s) for s in security_schemes)
        self._endpoints = dict(endpoints or {})
        self._capabilities = list(capabilities or [])

    @property
    def member_id(self):
        return self._member_id

    @property
    def resolved_schemes(self):
        """The declared schemes as our primitive names."""
        return self._schemes

    def public_view(self):
        """Unauthenticated discovery: capabilities + the auth contract
        (scheme names). NEVER endpoints (A2A §6.9 tiered disclosure)."""
        return {
            "member_id": self._member_id,
            "capabilities": list(self._capabilities),
            "security_schemes": sorted(self._schemes),
        }

    def authenticated_view(self):
        """Verified callers only: the public view + endpoints. The
        gate hands this out inside authorized call records; servers
        must never serve it to unverified callers."""
        view = self.public_view()
        view["endpoints"] = dict(self._endpoints)
        return view


class MeshCallGate(object):
    """Per-request auth: verify the envelope BEFORE routing (§7.3/§7.4).

    Built from the three existing verifiers (composed, never
    re-implemented): ``svid_control`` (a
    ``gov.svid_issuer.MeshControl``), ``ticket_issuer`` (a
    ``gov.scoped_tool_listing.ScopeTicketIssuer``), and
    ``credential_issuer`` (a
    ``gov.short_lived_credentials.CredentialIssuer``). Their refusal
    codes propagate unchanged; ``mesh-auth-*`` codes cover this
    contract layer's own decisions.
    """

    def __init__(self, svid_control, ticket_issuer, credential_issuer):
        if not hasattr(svid_control, "admit"):
            raise MeshAuthError(
                MALFORMED_CODE,
                "svid_control must expose admit() "
                "(gov.svid_issuer.MeshControl)")
        if not hasattr(ticket_issuer, "verify"):
            raise MeshAuthError(
                MALFORMED_CODE,
                "ticket_issuer must expose verify() "
                "(gov.scoped_tool_listing.ScopeTicketIssuer)")
        if not hasattr(credential_issuer, "verify"):
            raise MeshAuthError(
                MALFORMED_CODE,
                "credential_issuer must expose verify() "
                "(gov.short_lived_credentials.CredentialIssuer)")
        self._svid_control = svid_control
        self._ticket_issuer = ticket_issuer
        self._credential_issuer = credential_issuer

    def authorize_call(self, card, envelope, required_scopes=None,
                       required_scheme=None, subject=None, now=None):
        """Verify one mesh call's auth envelope. Returns the auth
        record ``{scheme, subject, scopes, member, dimensions,
        authenticated_card}``.

        Fail-closed order: card -> envelope present -> scheme
        declared -> scheme matches required -> credential verifies
        (the verifier's own codes propagate) -> subject binding (when
        ``subject`` is given) -> scope coverage. Anything failing
        refuses; nothing proceeds on a partial verification.
        """
        at = _validate_now(now)
        if not isinstance(card, MeshAuthCard):
            raise MeshAuthError(
                MALFORMED_CODE, "card must be a MeshAuthCard")
        if envelope is None:
            raise MeshAuthError(
                ENVELOPE_MISSING_CODE,
                "mesh call carries no auth envelope; refused before "
                "routing")
        if not isinstance(envelope, dict):
            raise MeshAuthError(
                MALFORMED_CODE, "auth envelope must be a dict")
        scheme = envelope.get("scheme")
        credential = envelope.get("credential", None)
        if not isinstance(scheme, str) or not scheme:
            raise MeshAuthError(
                MALFORMED_CODE, "auth envelope needs a non-empty "
                "'scheme' string")
        if scheme not in OUR_SCHEMES:
            raise MeshAuthError(
                MALFORMED_CODE,
                "auth envelope scheme %r is not a known primitive"
                % (scheme,))
        if scheme not in card.resolved_schemes:
            raise MeshAuthError(
                UNDECLARED_SCHEME_CODE,
                "scheme %r is not in member %r's declared "
                "securitySchemes %s (default-deny)"
                % (scheme, card.member_id,
                   sorted(card.resolved_schemes)))
        if required_scheme is not None and scheme != required_scheme:
            raise MeshAuthError(
                SCHEME_CONFUSION_CODE,
                "call requires scheme %r but the envelope presents "
                "scheme %r: schemes are never substituted for each "
                "other" % (required_scheme, scheme))
        subject_out, scopes = self._verify_credential(
            scheme, credential, subject, at)
        required = frozenset(required_scopes or ())
        if not required <= scopes:
            raise MeshAuthError(
                SCOPE_UNCOVERED_CODE,
                "credential scopes %s do not cover required scopes "
                "%s (exact-set, §7.5 scopes dimension)"
                % (sorted(scopes), sorted(required - scopes)))
        return {
            "scheme": scheme,
            "subject": subject_out,
            "scopes": sorted(scopes),
            "member": card.member_id,
            "dimensions": {
                "who": subject_out,
                "what": card.member_id,
                "scope": sorted(scopes),
                "context": {"now": at},
            },
            "authenticated_card": card.authenticated_view(),
        }

    def _verify_credential(self, scheme, credential, subject, at):
        """Verify the envelope credential under its scheme. Returns
        (subject_out, scopes). Underlying verifier codes propagate
        unchanged (composed, not re-implemented)."""
        if scheme == SCHEME_SVID:
            if not isinstance(credential, dict):
                raise MeshAuthError(
                    SCHEME_CONFUSION_CODE,
                    "svid scheme presented a non-SVID credential payload")
            spiffe_id = self._svid_control.admit(credential, now=at)
            # SVID is identity-only: it carries no call scopes.
            return spiffe_id, frozenset()
        if scheme == SCHEME_SCOPE_TICKET:
            if not isinstance(credential, str):
                raise MeshAuthError(
                    SCHEME_CONFUSION_CODE,
                    "scope-ticket scheme presented a non-ticket "
                    "credential payload")
            sub, scopes = self._ticket_issuer.verify(credential)
            if subject is not None:
                expect = hashlib.sha256(
                    subject.encode("utf-8")).hexdigest()
                if not hmac.compare_digest(sub, expect):
                    raise MeshAuthError(
                        SUBJECT_MISMATCH_CODE,
                        "scope ticket is bound to a different subject "
                        "than the authenticated %r" % (subject,))
                return subject, scopes
            # Standalone ticket: bearer capability, subject unproven
            # (honest residual, documented at module top).
            return "ticket:%s" % sub, scopes
        # scheme == SCHEME_SHORT_LIVED_CREDENTIAL
        if not isinstance(credential, dict) or \
                not credential.get("credential_id") or \
                not credential.get("secret"):
            raise MeshAuthError(
                SCHEME_CONFUSION_CODE,
                "short-lived-credential scheme presented a payload "
                "without credential_id/secret")
        record = self._credential_issuer.verify(
            credential["credential_id"], credential["secret"], now=at)
        return record["principal"], frozenset([record["scope"]])


class MeshTaskAuth(object):
    """Mid-task escalation state machine (A2A §7.6 shape).

    ``begin`` -> active; ``escalate`` -> AUTH_REQUIRED (paused);
    ``resume`` -> active (only on re-auth with the escalated scheme);
    ``abandon`` -> terminal. While AUTH_REQUIRED, every ``call``
    refuses ``mesh-auth-task-paused`` WITHOUT evaluating the
    envelope — the task stays paused, never proceeds, never fails
    silently. ``resume`` with the old/weaker scheme refuses
    ``mesh-auth-escalation-bypass`` and stays paused.

    The escalation record (what scheme/credential is needed + why) is
    the fulfillment contract the caller satisfies OUT-OF-BAND: the
    needed credential never transits the task's own channel.
    """

    def __init__(self, gate):
        if not isinstance(gate, MeshCallGate):
            raise MeshAuthError(
                MALFORMED_CODE, "gate must be a MeshCallGate")
        self._gate = gate
        self._tasks = {}

    def _get(self, task_id):
        task = self._tasks.get(task_id)
        if task is None:
            raise MeshAuthError(
                MALFORMED_CODE, "unknown task %r" % (task_id,))
        return task

    def begin(self, task_id):
        """Start a task in the active state."""
        if not isinstance(task_id, str) or not task_id:
            raise MeshAuthError(
                MALFORMED_CODE, "task_id must be a non-empty string")
        if task_id in self._tasks:
            raise MeshAuthError(
                MALFORMED_CODE, "task %r already begun" % (task_id,))
        self._tasks[task_id] = {
            "state": TASK_STATE_ACTIVE,
            "required_scheme": None,
            "reason": None,
            "history": [("begin", TASK_STATE_ACTIVE)],
        }
        return TASK_STATE_ACTIVE

    def state(self, task_id):
        """The task's machine-coded state."""
        return self._get(task_id)["state"]

    def call(self, task_id, card, envelope, required_scopes=None,
             now=None):
        """Authorize one call on an ACTIVE task. On an
        AUTH_REQUIRED task the call refuses task-paused WITHOUT
        touching the envelope; the task stays paused."""
        task = self._get(task_id)
        if task["state"] == TASK_STATE_ABANDONED:
            raise MeshAuthError(
                MALFORMED_CODE, "task %r is abandoned" % (task_id,))
        if task["state"] == TASK_STATE_AUTH_REQUIRED:
            task["history"].append(("call-refused", TASK_STATE_AUTH_REQUIRED))
            raise MeshAuthError(
                TASK_PAUSED_CODE,
                "task %r is paused in AUTH_REQUIRED (needs %r: %s); "
                "resume with the required scheme — the task never "
                "proceeds unauthenticated"
                % (task_id, task["required_scheme"], task["reason"]))
        return self._gate.authorize_call(
            card, envelope, required_scopes=required_scopes, now=now)

    def escalate(self, task_id, required_scheme, reason, now=None):
        """Pause the task: it now needs ``required_scheme`` auth to
        continue. Returns the escalation record (the §7.6 message:
        what is needed and why), fulfilled out-of-band."""
        task = self._get(task_id)
        if task["state"] != TASK_STATE_ACTIVE:
            raise MeshAuthError(
                MALFORMED_CODE,
                "escalate needs an active task (task %r is %r)"
                % (task_id, task["state"]))
        if required_scheme not in OUR_SCHEMES:
            raise MeshAuthError(
                MALFORMED_CODE,
                "required_scheme %r is not one of %s"
                % (required_scheme, sorted(OUR_SCHEMES)))
        if not isinstance(reason, str) or not reason.strip():
            raise MeshAuthError(
                MALFORMED_CODE, "escalation needs a human-readable reason")
        at = _validate_now(now)
        task["state"] = TASK_STATE_AUTH_REQUIRED
        task["required_scheme"] = required_scheme
        task["reason"] = reason.strip()
        task["history"].append(("escalate", TASK_STATE_AUTH_REQUIRED))
        return {
            "task": task_id,
            "state": TASK_STATE_AUTH_REQUIRED,
            "required_scheme": required_scheme,
            "reason": task["reason"],
            "at": at,
        }

    def resume(self, task_id, card, envelope, subject=None, now=None):
        """Re-authenticate a paused task. ONLY the escalated scheme
        is accepted: presenting the old/weaker scheme refuses
        ``mesh-auth-escalation-bypass`` and the task stays paused.
        On success the task returns to active. ``subject`` is the
        paired SVID identity for subject-bound schemes (the
        scope-ticket case)."""
        task = self._get(task_id)
        if task["state"] != TASK_STATE_AUTH_REQUIRED:
            raise MeshAuthError(
                MALFORMED_CODE,
                "resume needs an AUTH_REQUIRED task (task %r is %r)"
                % (task_id, task["state"]))
        if not isinstance(envelope, dict) or \
                envelope.get("scheme") != task["required_scheme"]:
            task["history"].append(
                ("resume-bypass-refused", TASK_STATE_AUTH_REQUIRED))
            raise MeshAuthError(
                ESCALATION_BYPASS_CODE,
                "task %r requires re-auth with scheme %r; presenting "
                "%r is an escalation bypass — the task stays paused"
                % (task_id, task["required_scheme"],
                   (envelope or {}).get("scheme")
                   if isinstance(envelope, dict) else None))
        record = self._gate.authorize_call(
            card, envelope, required_scheme=task["required_scheme"],
            subject=subject, now=now)
        task["state"] = TASK_STATE_ACTIVE
        task["required_scheme"] = None
        task["reason"] = None
        task["history"].append(("resume", TASK_STATE_ACTIVE))
        return record

    def abandon(self, task_id):
        """Terminal: the task will never resume."""
        task = self._get(task_id)
        task["state"] = TASK_STATE_ABANDONED
        task["history"].append(("abandon", TASK_STATE_ABANDONED))
        return TASK_STATE_ABANDONED

    def escalation_record(self, task_id):
        """The outstanding escalation (None unless AUTH_REQUIRED)."""
        task = self._get(task_id)
        if task["state"] != TASK_STATE_AUTH_REQUIRED:
            return None
        return {
            "task": task_id,
            "state": TASK_STATE_AUTH_REQUIRED,
            "required_scheme": task["required_scheme"],
            "reason": task["reason"],
        }
