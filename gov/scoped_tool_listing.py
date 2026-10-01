"""Scope-gated tool listing (wave-262 lane 1, MCP D1 ADAPT).

Adapts THREE MCP-spec mechanisms as PROSE ONLY (no spec text read,
copied, imported, or vendored; the spec is a protocol document, not
code, and is never a dependency here):

1. **Scope-gated tool listing.** MCP's spec states a server's tool set
   "MAY vary by the authorization presented on the request — for
   example, returning only the tools the caller's granted scopes
   permit." Here: :class:`ToolRegistry` returns, per caller, ONLY the
   tools their scopes permit. Listing is itself authorization-relevant:
   an unpermitted tool's existence is never confirmed by the listing.
2. **Human-in-the-loop UX contract.** The spec's trust-&-safety warning
   mandates showing WHICH tools are exposed, WHAT is being invoked, and
   a confirm/deny surface. Here: :func:`build_approval_request` builds
   the structured approval-request shape (action, scopes, what the tool
   would do, the caller's subject digest) and :func:`enqueue_approval`
   hands it to the existing approval queue — the exact
   ``ApprovalQueue.queue()`` seam, no duplicated queue machinery.
3. **Elicitation URL-mode consent.** MCP's ``elicitation/create`` has a
   ``url`` mode: out-of-band consent where "data (other than the URL
   itself) is not exposed to the client." Here: :class:`ConsentIssuer`
   mints MAC-bound consent tokens that the human presents out-of-band
   via :func:`confirm_consent`; the consent is recorded in the audit
   log by DIGEST only. This is the user-facing half of our sentinel
   credential substitution (``gov.sentinel_substitution``): the agent
   never holds raw secrets (sentinels only), and the human never acts
   through the agent's channel (out-of-band consent only).

Identity binding: scopes are sealed into an HMAC ticket bound to the
caller's SUBJECT DIGEST (sha256 of the verified SVID spiffe_id — this
module does NOT verify SVIDs itself; call sites pass the output of
``gov.svid_issuer.SvidVerifier.verify`` and hash the ``spiffe_id``).
The registry enforces the binding when the deployment asserts the
presenter: :meth:`ToolRegistry.invoke` / :meth:`ToolRegistry.list_tools`
take an optional ``expected_subject``; a mismatch with the ticket's
bound subject refuses ``scope-listing-subject-mismatch``. Without an
asserted presenter the ticket is holder-usable (documented): the
binding is only as strong as the presenter's asserted identity, and
the trust anchor for "who is presenting" still comes from the
deployment (``gov.svid_issuer`` / ``gov.mcp_invocation_authz``) — this
layer compares digests, it does not mint identities.

Protocol separation (F241): scope tickets and consent tokens are
sealed under DIFFERENT MAC domains (the w244 house pattern:
``gov.token_scope_enforcement`` separates its grant and policy MACs
with ``_GRANT_DOMAIN``/``_POLICY_DOMAIN``). A token sealed for one
protocol never verifies under the other, even under a shared
deployment key. Honest migration note: sealed values minted before
this domain separation refuse ``scope-grant-tampered`` / fail
consent verification — fail-closed, no silent downgrade; deployments
re-mint after upgrade (consent tokens are 300s-TTL by default;
scope tickets are re-sealed on the next issuance).

Composition with the W244 layer: ``gov.token_scope_enforcement``
enforces per-call scope coverage for token-bound MCP calls; this
registry's :meth:`ToolRegistry.invoke` is the LISTING-bound choke
(the tool named must be in the caller's visible set). Deployments
using transactional tokens run ``check_scope`` first, then this
registry's ``invoke`` — the two layers never duplicate each other.

Fail-closed rules (all machine-coded):
- Unknown scope (at seal or register time) -> ``scope-listing-unknown-scope``.
- Scope confusion (``read`` vs ``read-admin``, prefix/suffix tricks) ->
  EXACT-match only; a near-miss never covers -> ``scope-listing-denied``.
- Listing with no/empty scopes -> EMPTY list, never the full set.
- Unregistered tool invocation with a verified ticket ->
  ``scope-listing-not-registered`` (deliberate post-auth residual).
- Pre-auth order-of-checks (F242): ``invoke`` verifies the sealed
  ticket BEFORE consulting the tool registry. A forged/malformed
  ticket -> ``scope-grant-tampered`` for EVERY tool name (no existence
  signal); a missing ticket -> ``scope-listing-denied`` for every
  non-public name (zero-scope public tools stay invokable, consistent
  with ``list_tools(None)``).
- Tampered sealed ticket -> ``scope-grant-tampered`` (reused from the
  token-scope domain: a sealed scope ticket IS a scope grant; tamper is
  reported as tamper, never as a scope gap).
- Presenter mismatch (F240): when the caller asserts a presenter
  subject, it MUST equal the ticket's bound subject (constant-time
  compare) -> ``scope-listing-subject-mismatch`` on mismatch.
- Forged/expired/mis-bound consent -> ``scope-consent-forged`` /
  ``scope-consent-expired`` / ``scope-consent-unbound``.
- Cross-protocol presentation (F241): a consent token presented as a
  scope ticket -> ``scope-grant-tampered`` (MAC domain mismatch); a
  scope ticket presented as a consent token -> ``scope-consent-forged``.
- A consent is recorded ONLY through :func:`confirm_consent` with a
  human-presented valid token. There is no other recording path: the
  "approval recorded without the human step" attack has no API to call.

Stdlib only. Deterministic: injectable clock (``now`` args), no I/O,
no network, no in-repo git subprocesses.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import time

os.environ.setdefault("GOV_DEPLOYMENT_MODE", "staging")

# New decision codes introduced by this module (see gov/decision_codes.py).
CODES = (
    "scope-consent-expired",
    "scope-consent-forged",
    "scope-consent-unbound",
    "scope-listing-denied",
    "scope-listing-not-registered",
    "scope-listing-subject-mismatch",
    "scope-listing-unknown-scope",
)

# Reused (not new): "scope-grant-tampered" for sealed-ticket tamper.

_SCOPE_TICKET_VERSION = 1
_CONSENT_TOKEN_VERSION = 1

# F241: per-protocol MAC domains. Scope tickets and consent tokens are
# sealed under different domains (w244 house pattern), so a token
# minted for one protocol never verifies under the other even when a
# deployment shares one key across both issuers. The domain enters the
# MAC input, not the JSON body: cross-presentation fails closed on MAC
# mismatch with no format change.
_SCOPE_TICKET_DOMAIN = "scope-ticket.v1"
_CONSENT_TOKEN_DOMAIN = "consent-token.v1"
_DOMAIN_PREFIX = b"gov.scoped_tool_listing\x00"

# Sentinel prefix the agent's args must carry instead of raw secrets.
# The approval shape refuses (fail-closed) args that do NOT look
# sentinel-bearing when they claim to be; pairing with
# gov/sentinel_substitution is a discipline contract documented here,
# not a value the module can verify (it cannot know the real values).
class ScopedListingError(Exception):
    """Machine-coded refusal. ``code`` is a decision-code taxonomy key."""

    def __init__(self, code, detail=""):
        super(ScopedListingError, self).__init__(
            "%s: %s" % (code, detail))
        self.code = code
        self.detail = detail


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("utf-8")


def _b64e(raw):
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64d(text):
    if not isinstance(text, str) or not text:
        raise ScopedListingError(
            "scope-grant-tampered", "malformed sealed value")
    try:
        pad = "=" * (-len(text) % 4)
        return base64.urlsafe_b64decode(text + pad)
    except Exception:
        raise ScopedListingError(
            "scope-grant-tampered", "malformed sealed value")


def _domain_bytes(domain):
    return _DOMAIN_PREFIX + domain.encode("ascii") + b"\x00"


def _seal(key, payload, domain):
    """MAC-bind ``payload`` under ``domain``; returns an opaque str.

    The domain is part of the MAC input (F241): sealed values are
    protocol-bound, so cross-protocol presentation fails closed.
    """
    body = _canonical(payload)
    mac = hmac.new(key, _domain_bytes(domain) + body,
                   hashlib.sha256).digest()
    return _b64e(body) + "." + _b64e(mac)


def _open(key, sealed, domain):
    """Verify a sealed value under ``domain``; returns the payload.

    A value sealed under a different domain (or a tampered one)
    refuses ``scope-grant-tampered`` — never a protocol-specific
    code, so callers cannot mistake cross-protocol confusion for a
    same-protocol defect.
    """
    if not isinstance(sealed, str) or sealed.count(".") != 1:
        raise ScopedListingError(
            "scope-grant-tampered", "malformed sealed value")
    body_b64, mac_b64 = sealed.split(".")
    body = _b64d(body_b64)
    expect = hmac.new(key, _domain_bytes(domain) + body,
                      hashlib.sha256).digest()
    try:
        presented = _b64d(mac_b64)
    except ScopedListingError:
        raise ScopedListingError(
            "scope-grant-tampered", "sealed value MAC unparseable")
    if not hmac.compare_digest(presented, expect):
        raise ScopedListingError(
            "scope-grant-tampered", "sealed value MAC mismatch")
    try:
        return json.loads(body.decode("utf-8"))
    except Exception:
        raise ScopedListingError(
            "scope-grant-tampered", "sealed value body unparseable")


def _check_universe(universe, scopes, what):
    unknown = [s for s in scopes if s not in universe]
    if unknown:
        raise ScopedListingError(
            "scope-listing-unknown-scope",
            "%s carries scope(s) outside the declared universe: %r"
            % (what, sorted(unknown)[:3]))


class ScopeTicketIssuer(object):
    """Seals caller scope sets into HMAC tickets bound to a subject.

    ``universe`` is the deployment's CLOSED scope vocabulary (exact
    strings; ``files:read`` and ``files:read-admin`` are different
    members — no prefix logic anywhere). ``key`` is the deployment
    secret (no dev-key fallback: a missing/empty key refuses at
    construction).
    """

    def __init__(self, key, universe):
        if not key:
            raise ScopedListingError(
                "scope-grant-tampered",
                "scope ticket issuer needs a deployment key")
        self._key = bytes(key)
        self._universe = frozenset(universe)

    @property
    def universe(self):
        return self._universe

    def seal(self, subject_digest, scopes, now=None):
        """Bind ``scopes`` to ``subject_digest``; returns an opaque str.

        Unknown scopes refuse ``scope-listing-unknown-scope``
        fail-closed (the issuer never mints a ticket it cannot
        interpret).
        """
        if not isinstance(subject_digest, str) or not subject_digest:
            raise ScopedListingError(
                "scope-listing-unknown-scope", "subject digest is required")
        scopes = set(scopes or ())
        _check_universe(self._universe, scopes, "ticket")
        payload = {
            "v": _SCOPE_TICKET_VERSION,
            "sub": subject_digest,
            "scopes": sorted(scopes),
            "iat": float(time.time() if now is None else now),
            "nonce": secrets.token_hex(8),
        }
        return _seal(self._key, payload, _SCOPE_TICKET_DOMAIN)

    def verify(self, sealed):
        """Verify a sealed ticket; returns (subject_digest, frozenset).

        F241: the ticket is verified under the scope-ticket MAC domain;
        a consent token (or any other protocol's sealed value) refuses
        ``scope-grant-tampered`` even under a shared deployment key.
        """
        payload = _open(self._key, sealed, _SCOPE_TICKET_DOMAIN)
        if not isinstance(payload, dict) or payload.get("v") != \
                _SCOPE_TICKET_VERSION:
            raise ScopedListingError(
                "scope-grant-tampered", "sealed ticket version mismatch")
        sub = payload.get("sub")
        scopes = payload.get("scopes")
        if not isinstance(sub, str) or not sub or \
                not isinstance(scopes, list) or \
                any(not isinstance(s, str) for s in scopes):
            raise ScopedListingError(
                "scope-grant-tampered", "sealed ticket shape invalid")
        # Belt and braces: the universe is closed at seal time, but a
        # ticket is re-checked on EVERY use — a scope that left the
        # universe since issuance refuses rather than silently passing.
        _check_universe(self._universe, scopes, "ticket")
        return sub, frozenset(scopes)


class ToolRegistry(object):
    """Registry of tools with declared required scopes.

    ``list_tools`` is the MCP-shaped discovery seam: it returns ONLY
    the tools the caller's ticket scopes permit. The listing never
    confirms an unpermitted tool's existence — no names, no scope
    metadata, no counts beyond the permitted subset.
    """

    def __init__(self, universe):
        self._universe = frozenset(universe)
        self._tools = {}
        self._issuer = None

    def bind_issuer(self, issuer):
        """Attach the ScopeTicketIssuer that mints this registry's tickets."""
        if issuer.universe != self._universe:
            raise ValueError(
                "issuer universe does not match registry universe")
        self._issuer = issuer
        return self

    def register(self, name, required_scopes, description,
                 input_schema=None, needs_consent=False):
        """Declare a tool. Deployment-owned (operator trust domain).

        ``required_scopes`` must be exact members of the universe.
        Re-registering a name with a DIFFERENT spec is a programmer
        error (ValueError); identical re-registration is idempotent.
        """
        if not isinstance(name, str) or not name:
            raise ValueError("tool name must be a non-empty string")
        required = frozenset(required_scopes or ())
        _check_universe(self._universe, required,
                        "tool %r" % (name,))
        spec = {
            "name": name,
            "required_scopes": required,
            "description": str(description or ""),
            "input_schema": input_schema,
            "needs_consent": bool(needs_consent),
        }
        prior = self._tools.get(name)
        if prior is not None and prior != spec:
            raise ValueError(
                "tool %r already registered with a different spec" % (name,))
        self._tools[name] = spec
        return self

    def _verified_ticket(self, sealed_ticket, expected_subject):
        """Verify the sealed ticket; returns (subject_digest, scopes).

        F240: when ``expected_subject`` is given, it MUST equal the
        ticket's bound subject (constant-time comparison) or the use
        refuses ``scope-listing-subject-mismatch``. The asserted
        presenter identity is deployment-supplied (the output of
        ``gov.svid_issuer`` / ``gov.mcp_invocation_authz``); this
        layer compares digests, it does not mint identities. When no
        presenter is asserted the ticket keeps its documented
        holder-usable semantics.
        """
        if sealed_ticket is None:
            # Listing/invocation with no scopes -> empty, never full.
            return None, frozenset()
        if self._issuer is None:
            raise ScopedListingError(
                "scope-listing-denied",
                "no ticket issuer bound: listing refuses fail-closed")
        sub, scopes = self._issuer.verify(sealed_ticket)
        if expected_subject is not None:
            if not isinstance(expected_subject, str) or not \
                    hmac.compare_digest(expected_subject.encode("utf-8"),
                                        sub.encode("utf-8")):
                raise ScopedListingError(
                    "scope-listing-subject-mismatch",
                    "presenter subject does not match the ticket's "
                    "bound subject")
        return sub, scopes

    def _view(self, spec):
        return {
            "name": spec["name"],
            "description": spec["description"],
            "input_schema": spec["input_schema"],
            "needs_consent": spec["needs_consent"],
            "required_scopes": sorted(spec["required_scopes"]),
        }

    def list_tools(self, sealed_ticket, expected_subject=None):
        """Return [(name, view)] for tools the ticket's scopes permit.

        Sorted by name, deterministic. Unpermitted tools are ABSENT —
        the listing is silence, not denial, so existence cannot be
        confirmed from it. F240: when ``expected_subject`` is given
        it must match the ticket's bound subject
        (``scope-listing-subject-mismatch`` on mismatch).
        """
        _sub, scopes = self._verified_ticket(sealed_ticket,
                                             expected_subject)
        out = []
        for name in sorted(self._tools):
            spec = self._tools[name]
            # Exact set comparison only: no prefix/substring matching.
            if spec["required_scopes"] <= scopes:
                out.append((name, self._view(spec)))
        return out

    def invoke(self, sealed_ticket, tool_name, action_fn, *args,
               expected_subject=None, **kwargs):
        """Run ``action_fn`` iff the ticket's scopes cover the tool.

        F242: the sealed ticket is verified BEFORE the tool registry
        is consulted, so no unauthenticated caller can distinguish
        absent names from present-but-scoped names: a forged/malformed
        ticket refuses ``scope-grant-tampered`` for EVERY tool name,
        and a missing ticket refuses ``scope-listing-denied`` for
        every non-public name (zero-scope public tools stay invokable,
        consistent with ``list_tools(None)``).

        Refusals are otherwise machine-coded:
        ``scope-listing-not-registered`` for unknown tools (with a
        verified ticket), ``scope-listing-denied`` for out-of-scope
        tools, ``scope-listing-subject-mismatch`` when the asserted
        presenter does not match the ticket's bound subject.
        (Deliberate residual: the two codes are distinguishable
        post-auth — see REPORT.md §residuals. Listing, the discovery
        seam, stays silent.)
        """
        _sub, scopes = self._verified_ticket(sealed_ticket,
                                             expected_subject)
        spec = self._tools.get(tool_name)
        if spec is None:
            if sealed_ticket is None:
                # F242: no pre-auth existence oracle — a missing ticket
                # refuses identically whether or not the name exists.
                raise ScopedListingError(
                    "scope-listing-denied",
                    "no ticket presented for tool %r" % (tool_name,))
            raise ScopedListingError(
                "scope-listing-not-registered",
                "tool %r is not registered" % (tool_name,))
        if not spec["required_scopes"] <= scopes:
            raise ScopedListingError(
                "scope-listing-denied",
                "ticket scopes do not cover tool %r" % (tool_name,))
        return action_fn(*args, **kwargs)


def build_approval_request(tool_name, tool_view, caller_scopes,
                           subject_digest, what_it_would_do, consent_url,
                           args):
    """Build the human-in-the-loop approval-request shape (MCP UX contract).

    The shape answers the spec's three questions: WHICH tool is exposed
    (``tool`` + required scopes), WHAT is being invoked
    (``what_it_would_do`` human text + args), and the confirm/deny
    surface (``consent_url``, the out-of-band elicitation URL).
    ``args`` MUST be sentinel-bearing (``fake_value_<uuid>``) per
    ``gov.sentinel_substitution`` — real credentials never ride the
    approval shape; that pairing is a caller discipline documented
    here, enforced at the substitution seams over there.
    """
    if not isinstance(tool_name, str) or not tool_name:
        raise ScopedListingError(
            "scope-listing-not-registered", "approval shape needs a tool")
    if not isinstance(what_it_would_do, str) or not what_it_would_do.strip():
        raise ScopedListingError(
            "scope-listing-denied",
            "approval shape needs a human-readable action description")
    return {
        "tool": tool_name,
        "required_scopes": sorted(
            (tool_view or {}).get("required_scopes", ()) or ()),
        "needs_consent": bool((tool_view or {}).get("needs_consent", False)),
        "caller_scopes": sorted(set(caller_scopes or ())),
        "caller_subject_digest": subject_digest,
        "what_it_would_do": what_it_would_do,
        "consent_url": consent_url,
        "args": dict(args or {}),
    }


def enqueue_approval(queue, shape, caller_identity, decision=None):
    """Hand the approval-request shape to the approval queue (the seam).

    This is the EXACT ``ApprovalQueue.queue()`` seam from
    ``gov/approvals.py``: ``action`` carries the tool + sentinel args +
    the human description; ``preview`` is the approver-facing display
    (sanitized again inside the queue per F11); ``policy_flag`` is the
    machine queue reason; ``caller_identity`` is the executor-minted
    ``AgentIdentity`` the queue authenticates (F42) — it must NOT be
    None, and this adapter refuses fail-closed before the queue's own
    check. Returns the approval id. No queue machinery is duplicated.
    """
    if caller_identity is None:
        raise ScopedListingError(
            "scope-listing-denied",
            "enqueue_approval refused: caller_identity is required (the "
            "queue's F42 minted-identity check)")
    if not isinstance(shape, dict) or not shape.get("tool"):
        raise ScopedListingError(
            "scope-listing-not-registered",
            "enqueue_approval refused: malformed approval shape")
    action = {
        "tool": shape["tool"],
        "args": dict(shape.get("args") or {}),
        "justification": shape.get("what_it_would_do", ""),
        "required_scopes": list(shape.get("required_scopes") or []),
        "caller_subject_digest": shape.get("caller_subject_digest"),
        "consent_url": shape.get("consent_url"),
    }
    preview = ("[scope-gated tool] %s\n%s\nOut-of-band consent: %s"
               % (shape["tool"], shape.get("what_it_would_do", ""),
                  shape.get("consent_url") or "n/a"))
    return queue.queue(action, decision, preview=preview,
                       policy_flag="scope-listing-consent",
                       caller_identity=caller_identity)


class ConsentIssuer(object):
    """Elicitation URL-mode consent: out-of-band, MAC-bound, audited.

    The human approves on a URL carrying an opaque token; the agent
    never sees the token and cannot mint one. ``confirm_consent`` is
    the ONLY path that records a consent — there is no API for
    "record approval without the human step."
    """

    def __init__(self, key, ttl_seconds=300):
        if not key:
            raise ScopedListingError(
                "scope-consent-forged",
                "consent issuer needs a deployment key")
        if not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise ScopedListingError(
                "scope-consent-forged", "consent TTL must be positive")
        self._key = bytes(key)
        self._ttl = float(ttl_seconds)

    def mint_consent_url(self, approval_id, tool_name, scopes,
                         subject_digest, now, base_url):
        """Mint the out-of-band consent URL for one (approval, tool).

        F241: the token is sealed under the consent-token MAC domain,
        so it never verifies as a scope ticket even when a deployment
        shares one key across both issuers.
        """
        if not approval_id or not tool_name or not subject_digest:
            raise ScopedListingError(
                "scope-consent-forged",
                "consent needs approval_id, tool_name, subject_digest")
        payload = {
            "v": _CONSENT_TOKEN_VERSION,
            "approval_id": approval_id,
            "tool": tool_name,
            "scopes": sorted(set(scopes or ())),
            "sub": subject_digest,
            "iat": float(now),
            "exp": float(now) + self._ttl,
            "nonce": secrets.token_hex(8),
        }
        token = _seal(self._key, payload, _CONSENT_TOKEN_DOMAIN)
        base = (base_url or "").rstrip("/")
        return "%s?ct=%s" % (base, token)

    def confirm_consent(self, token, approval_id, tool_name,
                        subject_digest, now, audit_sink):
        """Human-presented token -> verify, bind, audit. Returns True.

        Fail-closed: forged MAC -> ``scope-consent-forged``; past TTL ->
        ``scope-consent-expired``; valid MAC but bound to a different
        approval/tool/subject -> ``scope-consent-unbound``. F241: a
        sealed value minted for another protocol (e.g. a scope ticket)
        refuses ``scope-consent-forged`` — the MAC domain mismatch is
        reported as forgery, never as expiry. Nothing is audited on
        refusal. On success the audit event records the token's DIGEST
        — never the token.
        """
        try:
            payload = _open(self._key, token, _CONSENT_TOKEN_DOMAIN)
        except ScopedListingError:
            raise ScopedListingError(
                "scope-consent-forged",
                "consent token is not genuine")
        if not isinstance(payload, dict) or payload.get("v") != \
                _CONSENT_TOKEN_VERSION:
            raise ScopedListingError(
                "scope-consent-forged", "consent token version mismatch")
        if float(now) > float(payload.get("exp", 0)):
            raise ScopedListingError(
                "scope-consent-expired", "consent token expired")
        bound = (payload.get("approval_id") == approval_id and
                 payload.get("tool") == tool_name and
                 payload.get("sub") == subject_digest)
        if not bound:
            raise ScopedListingError(
                "scope-consent-unbound",
                "consent token is bound to a different "
                "approval/tool/subject")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        audit_sink({
            "event": "scope-consent-confirmed",
            "approval_id": approval_id,
            "tool": tool_name,
            "subject_digest": subject_digest,
            "scopes": sorted(payload.get("scopes") or ()),
            "consent_digest": digest,
            "issued_at": payload.get("iat"),
            "decided_at": float(now),
        })
        return True
